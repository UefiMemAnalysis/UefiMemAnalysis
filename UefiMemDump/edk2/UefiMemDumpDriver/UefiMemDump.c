/** @file
  UEFI memory dump driver.

  This driver performs an offline memory acquisition near end of boot, writes a
  memory map, image list, and raw dump chunks to a selected USB target.

  Security and safety notes:
  - Target media is selected using policy constraints (USB path + optional removable +
    minimum size).
  - High-risk descriptor types are zero-filled instead of direct reads.
  - The implementation prefers fail-closed behavior on ambiguous/invalid states.
**/

#include "UefiMemDump.h"
#include "UefiImageList.h"

#define DUMP_DIR_NAME              L"\\Dump"
#define DUMP_MEM_MAP_FILE_NAME     L"Memory_Map.txt"
#define DUMP_IMAGE_LIST_FILE_NAME  L"ImageList.txt"

// CHANGE: USB target selection is now policy-based (capacity/path), no marker file.
#define DUMP_MIN_TARGET_MEDIA_BYTES    (0ULL)                                  // Optional floor; 0 means disabled.
#define DUMP_MEDIA_SIZE_MARGIN_BYTES   (1ULL  * 1024ULL * 1024ULL * 1024ULL)  // Optional headroom over required dump size.
#define DUMP_REQUIRE_REMOVABLE_MEDIA   FALSE
#define DUMP_REQUIRE_USB_DEVICE_PATH   TRUE
#define DUMP_FAIL_IF_AMBIGUOUS_TARGET  FALSE
#define DUMP_LOG_SELECTION_DETAILS     TRUE

#define DUMP_LOG_INFO(...)  DEBUG ((DEBUG_INFO,  "[UefiMemDump] " __VA_ARGS__))
#define DUMP_LOG_WARN(...)  DEBUG ((DEBUG_WARN,  "[UefiMemDump] " __VA_ARGS__))
#define DUMP_LOG_ERR(...)   DEBUG ((DEBUG_ERROR, "[UefiMemDump] " __VA_ARGS__))

STATIC EFI_HANDLE  mImageHandle                    = NULL;
STATIC EFI_EVENT   mReadyToBootEvent               = NULL;
STATIC EFI_EVENT   mBeforeExitBootServicesEvent    = NULL;
STATIC BOOLEAN     mDumpTriggered                  = FALSE;
STATIC BOOLEAN     mCollectImageList               = TRUE;

STATIC
CONST CHAR16 *
MemoryTypeToStr (
  IN UINT32  Type
  )
{
  switch (Type) {
    case EfiReservedMemoryType:
      return L"EfiReservedMemoryType";
    case EfiLoaderCode:
      return L"EfiLoaderCode";
    case EfiLoaderData:
      return L"EfiLoaderData";
    case EfiBootServicesCode:
      return L"EfiBootServicesCode";
    case EfiBootServicesData:
      return L"EfiBootServicesData";
    case EfiRuntimeServicesCode:
      return L"EfiRuntimeServicesCode";
    case EfiRuntimeServicesData:
      return L"EfiRuntimeServicesData";
    case EfiConventionalMemory:
      return L"EfiConventionalMemory";
    case EfiUnusableMemory:
      return L"EfiUnusableMemory";
    case EfiACPIReclaimMemory:
      return L"EfiACPIReclaimMemory";
    case EfiACPIMemoryNVS:
      return L"EfiACPIMemoryNVS";
    case EfiMemoryMappedIO:
      return L"EfiMemoryMappedIO";
    case EfiMemoryMappedIOPortSpace:
      return L"EfiMemoryMappedIOPortSpace";
    case EfiPalCode:
      return L"EfiPalCode";
    default:
      return L"Unknown Memory Type";
  }
}

STATIC
INTN
EFIAPI
CompareRegionsByStart (
  IN CONST VOID  *Left,
  IN CONST VOID  *Right
  )
{
  CONST REGION  *A;
  CONST REGION  *B;

  A = (CONST REGION *)Left;
  B = (CONST REGION *)Right;

  if (A->StartAddress < B->StartAddress) {
    return -1;
  }

  if (A->StartAddress > B->StartAddress) {
    return 1;
  }

  return 0;
}

STATIC
EFI_STATUS
CollectMemoryRegions (
  OUT REGION                 **Regions,
  IN  UINTN                  RegionsCount,
  IN  UINTN                  DescriptorSize,
  IN  EFI_MEMORY_DESCRIPTOR  *MemoryMap
  )
{
  REGION                 *Array;
  EFI_MEMORY_DESCRIPTOR  *Descriptor;
  UINTN                  Index;
  UINT64                 RegionBytes;
  UINT64                 RegionEnd;

  if ((Regions == NULL) || (MemoryMap == NULL) || (DescriptorSize == 0)) {
    return EFI_INVALID_PARAMETER;
  }

  *Regions = NULL;
  if (RegionsCount == 0) {
    return EFI_SUCCESS;
  }

  Array = AllocateZeroPool (sizeof (REGION) * RegionsCount);
  if (Array == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Descriptor = MemoryMap;
  for (Index = 0; Index < RegionsCount; Index++) {
    Array[Index].Type         = Descriptor->Type;
    Array[Index].StartAddress = Descriptor->PhysicalStart;
    Array[Index].Descriptor   = Descriptor;
    Array[Index].MemoryTypeString = MemoryTypeToStr (Descriptor->Type);

    if (Descriptor->NumberOfPages > (MAX_UINT64 / EFI_PAGE_SIZE)) {
      RegionEnd = MAX_UINT64;
    } else {
      RegionBytes = Descriptor->NumberOfPages * EFI_PAGE_SIZE;
      if ((RegionBytes == 0) || (Descriptor->PhysicalStart > (MAX_UINT64 - RegionBytes + 1))) {
        RegionEnd = MAX_UINT64;
      } else {
        RegionEnd = Descriptor->PhysicalStart + RegionBytes - 1;
      }
    }

    Array[Index].EndAddress = RegionEnd;
    Descriptor = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Descriptor + DescriptorSize);
  }

  *Regions = Array;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
CollectAndSortMemoryRanges (
  OUT REGION                 **Regions,
  OUT UINTN                  *RegionCount,
  IN  UINTN                  MemoryMapSize,
  IN  UINTN                  DescriptorSize,
  IN  EFI_MEMORY_DESCRIPTOR  *MemoryMap
  )
{
  EFI_STATUS  Status;
  REGION      TempElement;

  if ((Regions == NULL) || (RegionCount == NULL) || (DescriptorSize == 0) || (MemoryMap == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  *Regions     = NULL;
  *RegionCount = MemoryMapSize / DescriptorSize;
  Status       = CollectMemoryRegions (Regions, *RegionCount, DescriptorSize, MemoryMap);
  if (EFI_ERROR (Status) || (*RegionCount <= 1)) {
    return Status;
  }

  QuickSort (
    *Regions,
    *RegionCount,
    sizeof (REGION),
    CompareRegionsByStart,
    &TempElement
    );

  return EFI_SUCCESS;
}

STATIC
BOOLEAN
IsExcludedRegionType (
  IN UINT32   Type,
  IN BOOLEAN  ExcludeConventional,
  IN BOOLEAN  ExcludeReserved
  )
{
  if (ExcludeConventional && (Type == EfiConventionalMemory)) {
    return TRUE;
  }

  if (ExcludeReserved && (Type == EfiReservedMemoryType)) {
    return TRUE;
  }

  return FALSE;
}

STATIC
BOOLEAN
ShouldZeroFillRegion (
  IN UINT32  Type
  )
{
  // CHANGE: avoid direct reads from regions that can destabilize firmware/device state.
  return (BOOLEAN)(
           (Type == EfiReservedMemoryType) ||
           (Type == EfiMemoryMappedIO) ||
           (Type == EfiMemoryMappedIOPortSpace) ||
           (Type == EfiUnusableMemory)
           );
}

STATIC
UINTN
GetMemoryMapDumpSize (
  IN UINTN                  MemoryMapSize,
  IN UINTN                  DescriptorSize,
  IN EFI_MEMORY_DESCRIPTOR  *MemoryMap,
  IN BOOLEAN                ExcludeConventional,
  IN BOOLEAN                ExcludeReserved
  )
{
  EFI_MEMORY_DESCRIPTOR  *Descriptor;
  UINTN                  RegionsCount;
  UINTN                  Index;
  UINTN                  RegionSize;
  UINTN                  TotalSize;

  if ((DescriptorSize == 0) || (MemoryMap == NULL)) {
    return 0;
  }

  Descriptor   = MemoryMap;
  RegionsCount = MemoryMapSize / DescriptorSize;
  TotalSize    = 0;

  for (Index = 0; Index < RegionsCount; Index++) {
    if (!IsExcludedRegionType (Descriptor->Type, ExcludeConventional, ExcludeReserved)) {
      if (Descriptor->NumberOfPages > (MAX_UINTN / EFI_PAGE_SIZE)) {
        return MAX_UINTN;
      }

      RegionSize = (UINTN)(Descriptor->NumberOfPages * EFI_PAGE_SIZE);
      if (RegionSize > (MAX_UINTN - TotalSize)) {
        return MAX_UINTN;
      }

      TotalSize += RegionSize;
    }

    Descriptor = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Descriptor + DescriptorSize);
  }

  return TotalSize;
}

STATIC
EFI_STATUS
GetCurrentMemoryMap (
  OUT EFI_MEMORY_DESCRIPTOR  **MemoryMap,
  OUT UINTN                  *MemoryMapSize,
  OUT UINTN                  *DescriptorSize
  )
{
  EFI_STATUS             Status;
  EFI_MEMORY_DESCRIPTOR  *Buffer;
  UINTN                  LocalMapSize;
  UINTN                  LocalDescriptorSize;
  UINTN                  MapKey;
  UINT32                 DescriptorVersion;
  UINTN                  Attempt;

  if ((MemoryMap == NULL) || (MemoryMapSize == NULL) || (DescriptorSize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  *MemoryMap      = NULL;
  *MemoryMapSize  = 0;
  *DescriptorSize = 0;

  LocalMapSize        = 0;
  LocalDescriptorSize = 0;
  MapKey              = 0;
  DescriptorVersion   = 0;

  Status = gBS->GetMemoryMap (
                  &LocalMapSize,
                  NULL,
                  &MapKey,
                  &LocalDescriptorSize,
                  &DescriptorVersion
                  );
  if (Status != EFI_BUFFER_TOO_SMALL) {
    return Status;
  }

  if (LocalDescriptorSize == 0) {
    return EFI_DEVICE_ERROR;
  }

  LocalMapSize += (LocalDescriptorSize * 8);

  for (Attempt = 0; Attempt < 3; Attempt++) {
    Buffer = AllocateZeroPool (LocalMapSize);
    if (Buffer == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    Status = gBS->GetMemoryMap (
                    &LocalMapSize,
                    Buffer,
                    &MapKey,
                    &LocalDescriptorSize,
                    &DescriptorVersion
                    );
    if (!EFI_ERROR (Status)) {
      *MemoryMap      = Buffer;
      *MemoryMapSize  = LocalMapSize;
      *DescriptorSize = LocalDescriptorSize;
      return EFI_SUCCESS;
    }

    FreePool (Buffer);
    if (Status != EFI_BUFFER_TOO_SMALL) {
      return Status;
    }

    LocalMapSize += (LocalDescriptorSize * 8);
  }

  return EFI_BUFFER_TOO_SMALL;
}

/**
  Serialize the current UEFI memory map to a UTF-16 text file.
**/
STATIC
EFI_STATUS
DumpMemoryMap (
  IN EFI_FILE_PROTOCOL       *ParentDir,
  IN CHAR16                  *FileName,
  IN UINTN                   MemoryMapSize,
  IN UINTN                   DescriptorSize,
  IN EFI_MEMORY_DESCRIPTOR   *MemoryMap
  )
{
  EFI_STATUS             Status;
  EFI_FILE_PROTOCOL      *MemMapFile;
  EFI_MEMORY_DESCRIPTOR  *Descriptor;
  UINTN                  Index;
  UINTN                  Count;
  CHAR16                 LineBuffer[256];
  UINTN                  BufferSize;
  UINTN                  Length;
  UINT64                 Start;
  UINT64                 Pages;
  UINT64                 End;

  if ((ParentDir == NULL) || (FileName == NULL) || (MemoryMap == NULL) || (DescriptorSize == 0)) {
    return EFI_INVALID_PARAMETER;
  }

  Status = ParentDir->Open (
                        ParentDir,
                        &MemMapFile,
                        FileName,
                        EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE,
                        0
                        );
  if (!EFI_ERROR (Status)) {
    MemMapFile->Delete (MemMapFile);
    MemMapFile = NULL;
  }

  Status = ParentDir->Open (
                        ParentDir,
                        &MemMapFile,
                        FileName,
                        EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
                        0
                        );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = MemMapFile->SetPosition (MemMapFile, 0);
  if (EFI_ERROR (Status)) {
    MemMapFile->Close (MemMapFile);
    return Status;
  }

  Descriptor = MemoryMap;
  Count      = MemoryMapSize / DescriptorSize;
  for (Index = 0; Index < Count; Index++) {
    Start  = Descriptor->PhysicalStart;
    Pages  = Descriptor->NumberOfPages;
    if (Pages == 0) {
      End = Start;
    } else if (Pages > (MAX_UINT64 / EFI_PAGE_SIZE)) {
      End = MAX_UINT64;
    } else {
      End = Start + (Pages * EFI_PAGE_SIZE) - 1;
    }
    Length = UnicodeSPrint (
               LineBuffer,
               sizeof (LineBuffer),
               L"Index=%u  Type=%u (%s)  Start=0x%016lx  End=0x%016lx  #Pages=0x%lx  Attr=0x%lx\n",
               (UINT32)Index,
               Descriptor->Type,
               MemoryTypeToStr (Descriptor->Type),
               Start,
               End,
               Pages,
               Descriptor->Attribute
               );
    BufferSize = Length * sizeof (CHAR16);
    Status     = MemMapFile->Write (MemMapFile, &BufferSize, LineBuffer);
    if (EFI_ERROR (Status)) {
      break;
    }

    Descriptor = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Descriptor + DescriptorSize);
  }

  MemMapFile->Flush (MemMapFile);
  MemMapFile->Close (MemMapFile);
  return Status;
}

STATIC
EFI_STATUS
OpenDumpFile (
  IN  EFI_FILE_PROTOCOL  *DumpDirectory,
  IN  UINTN              DumpFileIndex,
  OUT EFI_FILE_PROTOCOL  **DumpFile
  )
{
  EFI_STATUS  Status;
  CHAR16      FileName[32];

  if ((DumpDirectory == NULL) || (DumpFile == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  UnicodeSPrint (FileName, sizeof (FileName), L"dump%u.bin", (UINT32)DumpFileIndex);
  Status = DumpDirectory->Open (
                          DumpDirectory,
                          DumpFile,
                          FileName,
                          EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
                          0
                          );
  return Status;
}

/**
  Stream selected memory regions into one or more dump*.bin files.

  Regions are chunked to bound temporary buffer usage and split by FAT32 max
  file size. High-risk region types are zero-filled instead of direct reads.
**/
STATIC
EFI_STATUS
DumpEntireMemory (
  IN EFI_FILE_PROTOCOL  *DumpDirectory,
  IN REGION             *Regions,
  IN UINTN              RegionCount,
  IN BOOLEAN            ExcludeConventional,
  IN BOOLEAN            ExcludeReserved
  )
{
  EFI_STATUS            Status;
  EFI_FILE_PROTOCOL     *DumpFile;
  UINTN                 DumpFileIndex;
  VOID                  *BatchBuffer;
  UINTN                 ProcessedInCurrentFile;
  UINTN                 Index;
  UINTN                 RegionSize;
  UINTN                 RegionOffset;
  UINTN                 ChunkSize;
  UINTN                 BufferOffset;
  UINTN                 RemainingInFile;
  UINTN                 RequestedWrite;
  UINT32                RegionType;
  EFI_PHYSICAL_ADDRESS  RegionStart;

  if ((DumpDirectory == NULL) || (Regions == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  BatchBuffer = AllocatePool (CHUNK_SIZE);
  if (BatchBuffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  DumpFile             = NULL;
  DumpFileIndex        = 1;
  ProcessedInCurrentFile = 0;

  Status = OpenDumpFile (DumpDirectory, DumpFileIndex, &DumpFile);
  if (EFI_ERROR (Status)) {
    FreePool (BatchBuffer);
    return Status;
  }

  for (Index = 0; Index < RegionCount; Index++) {
    RegionType = Regions[Index].Type;
    if (IsExcludedRegionType (RegionType, ExcludeConventional, ExcludeReserved)) {
      continue;
    }

    if (Regions[Index].Descriptor->NumberOfPages > (MAX_UINTN / EFI_PAGE_SIZE)) {
      Status = EFI_BAD_BUFFER_SIZE;
      break;
    }

    RegionSize  = (UINTN)(Regions[Index].Descriptor->NumberOfPages * EFI_PAGE_SIZE);
    RegionStart = Regions[Index].StartAddress;
    RegionOffset = 0;
    while (RegionOffset < RegionSize) {
      ChunkSize = RegionSize - RegionOffset;
      if (ChunkSize > CHUNK_SIZE) {
        ChunkSize = CHUNK_SIZE;
      }

      if (ShouldZeroFillRegion (RegionType)) {
        SetMem (BatchBuffer, ChunkSize, 0);
      } else {
        // Defensive bounds checks before mapping physical address into pointer space.
        if (RegionStart > (EFI_PHYSICAL_ADDRESS)MAX_UINTN) {
          Status = EFI_DEVICE_ERROR;
          goto Exit;
        }

        if (RegionOffset > (MAX_UINTN - (UINTN)RegionStart)) {
          Status = EFI_DEVICE_ERROR;
          goto Exit;
        }

        CopyMem (BatchBuffer, (VOID *)((UINTN)RegionStart + RegionOffset), ChunkSize);
      }

      BufferOffset = 0;
      while (BufferOffset < ChunkSize) {
        if (ProcessedInCurrentFile >= MAX_FILE_SIZE) {
          DumpFile->Close (DumpFile);
          DumpFile = NULL;
          DumpFileIndex++;
          ProcessedInCurrentFile = 0;
          Status = OpenDumpFile (DumpDirectory, DumpFileIndex, &DumpFile);
          if (EFI_ERROR (Status)) {
            goto Exit;
          }
        }

        RemainingInFile = MAX_FILE_SIZE - ProcessedInCurrentFile;
        RequestedWrite  = ChunkSize - BufferOffset;
        if (RequestedWrite > RemainingInFile) {
          RequestedWrite = RemainingInFile;
        }

        Status = DumpFile->Write (
                             DumpFile,
                             &RequestedWrite,
                             (UINT8 *)BatchBuffer + BufferOffset
                             );
        if (EFI_ERROR (Status) || (RequestedWrite == 0)) {
          if (!EFI_ERROR (Status)) {
            Status = EFI_DEVICE_ERROR;
          }

          goto Exit;
        }

        BufferOffset            += RequestedWrite;
        ProcessedInCurrentFile  += RequestedWrite;
      }

      RegionOffset += ChunkSize;
    }
  }

Exit:
  if (DumpFile != NULL) {
    DumpFile->Flush (DumpFile);
    DumpFile->Close (DumpFile);
  }

  if (BatchBuffer != NULL) {
    FreePool (BatchBuffer);
  }

  return Status;
}

STATIC
BOOLEAN
TryAddU64 (
  IN  UINT64  A,
  IN  UINT64  B,
  OUT UINT64  *Result
  )
{
  if (Result == NULL) {
    return FALSE;
  }

  if (A > (MAX_UINT64 - B)) {
    return FALSE;
  }

  *Result = A + B;
  return TRUE;
}

STATIC
BOOLEAN
GetMediaSizeBytes (
  IN  EFI_BLOCK_IO_PROTOCOL  *BlockIo,
  OUT UINT64                 *MediaSizeBytes
  )
{
  EFI_BLOCK_IO_MEDIA  *Media;
  UINT64              BlockCount;

  if ((BlockIo == NULL) || (MediaSizeBytes == NULL) || (BlockIo->Media == NULL)) {
    return FALSE;
  }

  Media = BlockIo->Media;
  if ((Media->BlockSize == 0) || (Media->LastBlock == MAX_UINT64)) {
    return FALSE;
  }

  BlockCount = Media->LastBlock + 1;
  if (BlockCount > (MAX_UINT64 / (UINT64)Media->BlockSize)) {
    return FALSE;
  }

  *MediaSizeBytes = BlockCount * (UINT64)Media->BlockSize;
  return TRUE;
}

STATIC
EFI_STATUS
HandleHasUsbMessagingNode (
  IN EFI_HANDLE  Handle
  )
{
  EFI_DEVICE_PATH_PROTOCOL  *DevicePath;
  EFI_DEVICE_PATH_PROTOCOL  *Node;
  UINT8                     SubType;

  DevicePath = DevicePathFromHandle (Handle);
  if (DevicePath == NULL) {
    return FALSE;
  }

  for (Node = DevicePath; !IsDevicePathEnd (Node); Node = NextDevicePathNode (Node)) {
    if (DevicePathType (Node) != MESSAGING_DEVICE_PATH) {
      continue;
    }

    SubType = DevicePathSubType (Node);
    if ((SubType == MSG_USB_DP) ||
        (SubType == MSG_USB_CLASS_DP) ||
        (SubType == MSG_USB_WWID_DP))
    {
      return TRUE;
    }
  }

  return FALSE;
}

STATIC
EFI_FILE_PROTOCOL *
FindUsbDrive (
  IN UINT64  RequiredDumpBytes
  )
{
  EFI_STATUS                        Status;
  EFI_HANDLE                        *FsHandles;
  UINTN                             FsCount;
  EFI_BLOCK_IO_PROTOCOL             *BlockIo;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL   *Fs;
  EFI_FILE_PROTOCOL                 *Root;
  EFI_FILE_PROTOCOL                 *BestRoot;
  UINTN                             Index;
  UINTN                             BestIndex;
  UINTN                             CandidateCount;
  UINT64                            MediaSizeBytes;
  UINT64                            RequiredMediaBytes;
  UINT64                            BestMediaSizeBytes;
  UINTN                             RejectedNoSfsProtocol;
  UINTN                             RejectedNoBlockIo;
  UINTN                             RejectedNotRemovable;
  UINTN                             RejectedReadOnly;
  UINTN                             RejectedNotUsbPath;
  UINTN                             RejectedMediaSizeParse;
  UINTN                             RejectedMediaBelowMin;
  UINTN                             RejectedMediaBelowRequired;
  UINTN                             RejectedOpenVolume;

  FsHandles = NULL;
  FsCount   = 0;
  BestRoot  = NULL;
  BestIndex = MAX_UINTN;
  CandidateCount = 0;
  BestMediaSizeBytes = 0;
  RejectedNoSfsProtocol       = 0;
  RejectedNoBlockIo           = 0;
  RejectedNotRemovable        = 0;
  RejectedReadOnly            = 0;
  RejectedNotUsbPath          = 0;
  RejectedMediaSizeParse      = 0;
  RejectedMediaBelowMin       = 0;
  RejectedMediaBelowRequired  = 0;
  RejectedOpenVolume          = 0;

  if (!TryAddU64 (RequiredDumpBytes, DUMP_MEDIA_SIZE_MARGIN_BYTES, &RequiredMediaBytes)) {
    RequiredMediaBytes = MAX_UINT64;
  }

  Status    = gBS->LocateHandleBuffer (
                     ByProtocol,
                     &gEfiSimpleFileSystemProtocolGuid,
                     NULL,
                     &FsCount,
                     &FsHandles
                     );
  if (EFI_ERROR (Status)) {
    DUMP_LOG_WARN ("USB selection failed at LocateHandleBuffer: %r\n", Status);
    return NULL;
  }

  DUMP_LOG_INFO (
    "USB selection start: handles=%u required_media=0x%lx min_media=0x%lx margin=0x%lx removable=%u usb_path=%u\n",
    (UINT32)FsCount,
    RequiredMediaBytes,
    DUMP_MIN_TARGET_MEDIA_BYTES,
    DUMP_MEDIA_SIZE_MARGIN_BYTES,
    (UINT32)DUMP_REQUIRE_REMOVABLE_MEDIA,
    (UINT32)DUMP_REQUIRE_USB_DEVICE_PATH
    );

  for (Index = 0; Index < FsCount; Index++) {
    Fs            = NULL;
    Root          = NULL;
    BlockIo       = NULL;
    MediaSizeBytes = 0;

    Status = gBS->OpenProtocol (
                    FsHandles[Index],
                    &gEfiSimpleFileSystemProtocolGuid,
                    (VOID **)&Fs,
                    mImageHandle,
                    NULL,
                    EFI_OPEN_PROTOCOL_GET_PROTOCOL
                    );
    if (EFI_ERROR (Status) || (Fs == NULL)) {
      RejectedNoSfsProtocol++;
      if (DUMP_LOG_SELECTION_DETAILS) {
        DUMP_LOG_INFO ("USB reject[%u]: OpenProtocol(SimpleFileSystem) failed: %r\n", (UINT32)Index, Status);
      }
      continue;
    }

    Status = gBS->OpenProtocol (
                    FsHandles[Index],
                    &gEfiBlockIoProtocolGuid,
                    (VOID **)&BlockIo,
                    mImageHandle,
                    NULL,
                    EFI_OPEN_PROTOCOL_GET_PROTOCOL
                    );
    if (EFI_ERROR (Status) || (BlockIo == NULL) || (BlockIo->Media == NULL)) {
      RejectedNoBlockIo++;
      if (DUMP_LOG_SELECTION_DETAILS) {
        DUMP_LOG_INFO ("USB reject[%u]: OpenProtocol(BlockIo) failed: %r\n", (UINT32)Index, Status);
      }
      continue;
    }

    if (DUMP_REQUIRE_REMOVABLE_MEDIA && !BlockIo->Media->RemovableMedia) {
      RejectedNotRemovable++;
      if (DUMP_LOG_SELECTION_DETAILS) {
        DUMP_LOG_INFO ("USB reject[%u]: media is not removable\n", (UINT32)Index);
      }
      continue;
    }

    if (BlockIo->Media->ReadOnly) {
      RejectedReadOnly++;
      if (DUMP_LOG_SELECTION_DETAILS) {
        DUMP_LOG_INFO ("USB reject[%u]: media is read-only\n", (UINT32)Index);
      }
      continue;
    }

    if (DUMP_REQUIRE_USB_DEVICE_PATH && !HandleHasUsbMessagingNode (FsHandles[Index])) {
      RejectedNotUsbPath++;
      if (DUMP_LOG_SELECTION_DETAILS) {
        DUMP_LOG_INFO ("USB reject[%u]: no USB messaging node in device path\n", (UINT32)Index);
      }
      continue;
    }

    if (!GetMediaSizeBytes (BlockIo, &MediaSizeBytes)) {
      RejectedMediaSizeParse++;
      if (DUMP_LOG_SELECTION_DETAILS) {
        DUMP_LOG_INFO (
          "USB reject[%u]: could not derive media size (BlockSize=0x%x LastBlock=0x%lx)\n",
          (UINT32)Index,
          BlockIo->Media->BlockSize,
          BlockIo->Media->LastBlock
          );
      }
      continue;
    }

    if (MediaSizeBytes < DUMP_MIN_TARGET_MEDIA_BYTES) {
      RejectedMediaBelowMin++;
      if (DUMP_LOG_SELECTION_DETAILS) {
        DUMP_LOG_INFO (
          "USB reject[%u]: media too small (media=0x%lx min=0x%lx)\n",
          (UINT32)Index,
          MediaSizeBytes,
          DUMP_MIN_TARGET_MEDIA_BYTES
          );
      }
      continue;
    }

    if (MediaSizeBytes < RequiredMediaBytes) {
      RejectedMediaBelowRequired++;
      if (DUMP_LOG_SELECTION_DETAILS) {
        DUMP_LOG_INFO (
          "USB reject[%u]: media below required size (media=0x%lx required_media=0x%lx)\n",
          (UINT32)Index,
          MediaSizeBytes,
          RequiredMediaBytes
          );
      }
      continue;
    }

    Status = Fs->OpenVolume (Fs, &Root);
    if (EFI_ERROR (Status) || (Root == NULL)) {
      RejectedOpenVolume++;
      if (DUMP_LOG_SELECTION_DETAILS) {
        DUMP_LOG_INFO ("USB reject[%u]: OpenVolume failed: %r\n", (UINT32)Index, Status);
      }
      continue;
    }

    CandidateCount++;
    DUMP_LOG_INFO (
      "USB candidate[%u]: media=0x%lx required_media=0x%lx\n",
      (UINT32)Index,
      MediaSizeBytes,
      RequiredMediaBytes
      );

    if ((BestRoot == NULL) || (MediaSizeBytes > BestMediaSizeBytes)) {
      if (BestRoot != NULL) {
        BestRoot->Close (BestRoot);
      }

      BestRoot          = Root;
      BestIndex         = Index;
      BestMediaSizeBytes = MediaSizeBytes;
    } else {
      Root->Close (Root);
    }
  }

  FreePool (FsHandles);
  DUMP_LOG_INFO (
    "USB selection summary: total=%u accepted=%u reject_sfs=%u reject_blockio=%u reject_nonremovable=%u reject_readonly=%u reject_nonusb=%u reject_mediasize=%u reject_min=%u reject_media_required=%u reject_openvolume=%u\n",
    (UINT32)FsCount,
    (UINT32)CandidateCount,
    (UINT32)RejectedNoSfsProtocol,
    (UINT32)RejectedNoBlockIo,
    (UINT32)RejectedNotRemovable,
    (UINT32)RejectedReadOnly,
    (UINT32)RejectedNotUsbPath,
    (UINT32)RejectedMediaSizeParse,
    (UINT32)RejectedMediaBelowMin,
    (UINT32)RejectedMediaBelowRequired,
    (UINT32)RejectedOpenVolume
    );

  if (CandidateCount == 0) {
    return NULL;
  }

  if (CandidateCount > 1) {
    if (DUMP_FAIL_IF_AMBIGUOUS_TARGET) {
      DUMP_LOG_WARN ("Multiple USB dump targets matched policy (%u). Aborting by policy.\n", (UINT32)CandidateCount);
      if (BestRoot != NULL) {
        BestRoot->Close (BestRoot);
      }

      return NULL;
    }

    DUMP_LOG_WARN ("Multiple USB dump targets matched policy (%u). Choosing largest media candidate.\n", (UINT32)CandidateCount);
  }

  if (BestRoot != NULL) {
    DUMP_LOG_INFO (
      "USB selected candidate[%u]: media=0x%lx\n",
      (UINT32)BestIndex,
      BestMediaSizeBytes
      );
  }

  return BestRoot;
}

/**
  Execute the full dump workflow:
  - acquire memory map
  - select writable USB target by policy
  - write image list and memory map
  - stream raw memory dump
**/
STATIC
EFI_STATUS
RunMemoryDump (
  IN EFI_HANDLE  ImageHandle
  )
{
  EFI_STATUS             Status;
  EFI_FILE_PROTOCOL      *RootDir;
  EFI_FILE_PROTOCOL      *DumpDir;
  EFI_MEMORY_DESCRIPTOR  *MemoryMap;
  UINTN                  MemoryMapSize;
  UINTN                  DescriptorSize;
  REGION                 *Regions;
  UINTN                  RegionCount;
  UINTN                  TotalMemorySize;
  BOOLEAN                ExcludeConventional;
  BOOLEAN                ExcludeReserved;

  // CHANGE: USB-only path. NTFS probing is intentionally removed.
  RootDir            = NULL;
  DumpDir            = NULL;
  MemoryMap          = NULL;
  MemoryMapSize      = 0;
  DescriptorSize     = 0;
  Regions            = NULL;
  RegionCount        = 0;
  ExcludeConventional = FALSE;
  ExcludeReserved    = FALSE;

  Status = GetCurrentMemoryMap (&MemoryMap, &MemoryMapSize, &DescriptorSize);
  if (EFI_ERROR (Status)) {
    DUMP_LOG_ERR ("GetCurrentMemoryMap failed: %r\n", Status);
    goto Cleanup;
  }

  TotalMemorySize = GetMemoryMapDumpSize (
                      MemoryMapSize,
                      DescriptorSize,
                      MemoryMap,
                      ExcludeConventional,
                      ExcludeReserved
                      );
  if ((TotalMemorySize == 0) || (TotalMemorySize == MAX_UINTN)) {
    Status = EFI_BAD_BUFFER_SIZE;
    DUMP_LOG_ERR ("Invalid total dump size computed: 0x%lx\n", TotalMemorySize);
    goto Cleanup;
  }

  DUMP_LOG_INFO (
    "USB policy: required_dump=0x%lx min_media=0x%lx margin=0x%lx removable=%u usb_path=%u ambiguous_fail=%u\n",
    (UINT64)TotalMemorySize,
    DUMP_MIN_TARGET_MEDIA_BYTES,
    DUMP_MEDIA_SIZE_MARGIN_BYTES,
    (UINT32)DUMP_REQUIRE_REMOVABLE_MEDIA,
    (UINT32)DUMP_REQUIRE_USB_DEVICE_PATH,
    (UINT32)DUMP_FAIL_IF_AMBIGUOUS_TARGET
    );

  RootDir = FindUsbDrive ((UINT64)TotalMemorySize);
  if (RootDir == NULL) {
    Status = EFI_NOT_FOUND;
    DUMP_LOG_WARN (
      "USB dump drive not found by policy. required_dump=0x%lx min_media=0x%lx margin=0x%lx removable=%u usb_path=%u ambiguous_fail=%u\n",
      (UINT64)TotalMemorySize,
      DUMP_MIN_TARGET_MEDIA_BYTES,
      DUMP_MEDIA_SIZE_MARGIN_BYTES,
      (UINT32)DUMP_REQUIRE_REMOVABLE_MEDIA,
      (UINT32)DUMP_REQUIRE_USB_DEVICE_PATH,
      (UINT32)DUMP_FAIL_IF_AMBIGUOUS_TARGET
      );
    goto Cleanup;
  }

  Status = RootDir->Open (
                      RootDir,
                      &DumpDir,
                      DUMP_DIR_NAME,
                      EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE,
                      0
                      );
  if (EFI_ERROR (Status)) {
    Status = RootDir->Open (
                        RootDir,
                        &DumpDir,
                        DUMP_DIR_NAME,
                        EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
                        EFI_FILE_DIRECTORY
                        );
  }

  if (EFI_ERROR (Status) || (DumpDir == NULL)) {
    DUMP_LOG_ERR ("Failed to open/create dump directory: %r\n", Status);
    goto Cleanup;
  }

  if (mCollectImageList) {
    // CHANGE: integrated image list collection logic from UefiMemDumpApp.
    Status = CollectLoadedImages (ImageHandle);
    if (!EFI_ERROR (Status)) {
      Status = WriteImageListToFile (DumpDir, DUMP_IMAGE_LIST_FILE_NAME);
      if (EFI_ERROR (Status)) {
        DUMP_LOG_WARN ("WriteImageListToFile failed: %r\n", Status);
      }
      FreeImageList ();
    } else {
      DUMP_LOG_WARN ("CollectLoadedImages failed: %r\n", Status);
    }
  }

  Status = DumpMemoryMap (DumpDir, DUMP_MEM_MAP_FILE_NAME, MemoryMapSize, DescriptorSize, MemoryMap);
  if (EFI_ERROR (Status)) {
    DUMP_LOG_ERR ("DumpMemoryMap failed: %r\n", Status);
    goto Cleanup;
  }

  Status = CollectAndSortMemoryRanges (
             &Regions,
             &RegionCount,
             MemoryMapSize,
             DescriptorSize,
             MemoryMap
             );
  if (EFI_ERROR (Status)) {
    DUMP_LOG_ERR ("CollectAndSortMemoryRanges failed: %r\n", Status);
    goto Cleanup;
  }

  Status = DumpEntireMemory (
             DumpDir,
             Regions,
             RegionCount,
             ExcludeConventional,
             ExcludeReserved
             );
  if (EFI_ERROR (Status)) {
    DUMP_LOG_ERR ("DumpEntireMemory failed: %r\n", Status);
    goto Cleanup;
  }

Cleanup:
  if (Regions != NULL) {
    FreePool (Regions);
  }

  if (MemoryMap != NULL) {
    FreePool (MemoryMap);
  }

  if (DumpDir != NULL) {
    DumpDir->Close (DumpDir);
  }

  if (RootDir != NULL) {
    RootDir->Close (RootDir);
  }

  return Status;
}

STATIC
VOID
EFIAPI
RegisterBeforeExitBootServicesCallback (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  EFI_STATUS  Status;

  if (mBeforeExitBootServicesEvent != NULL) {
    return;
  }

  Status = gBS->CreateEventEx (
                  EVT_NOTIFY_SIGNAL,
                  TPL_CALLBACK,
                  MemDumpCallback,
                  NULL,
                  &gEfiEventBeforeExitBootServicesGuid,
                  &mBeforeExitBootServicesEvent
                  );
  if (EFI_ERROR (Status)) {
    DUMP_LOG_ERR ("CreateEventEx(BeforeExitBootServices) failed: %r\n", Status);
  }

  if (mReadyToBootEvent != NULL) {
    gBS->CloseEvent (mReadyToBootEvent);
    mReadyToBootEvent = NULL;
  }
}

EFI_STATUS
EFIAPI
UefiMemDumpUnload (
  IN EFI_HANDLE  ImageHandle
  )
{
  EFI_STATUS  Status;

  if (mReadyToBootEvent != NULL) {
    gBS->CloseEvent (mReadyToBootEvent);
    mReadyToBootEvent = NULL;
  }

  if (mBeforeExitBootServicesEvent != NULL) {
    gBS->CloseEvent (mBeforeExitBootServicesEvent);
    mBeforeExitBootServicesEvent = NULL;
  }

  Status = gBS->UninstallMultipleProtocolInterfaces (
                  ImageHandle,
                  &gEfiDriverBindingProtocolGuid,
                  &gUefiMemDumpDriverBinding,
                  NULL
                  );

  return Status;
}

EFI_DRIVER_BINDING_PROTOCOL  gUefiMemDumpDriverBinding = {
  UefiMemDumpDriverBindingSupported,
  UefiMemDumpDriverBindingStart,
  UefiMemDumpDriverBindingStop,
  MEM_DRIVER_VERSION,
  NULL,
  NULL
};

EFI_STATUS
EFIAPI
UefiMemDumpDriverEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  mImageHandle = ImageHandle;

  Status = EfiLibInstallDriverBinding (
             ImageHandle,
             SystemTable,
             &gUefiMemDumpDriverBinding,
             ImageHandle
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = gBS->CreateEventEx (
                  EVT_NOTIFY_SIGNAL,
                  TPL_CALLBACK,
                  RegisterBeforeExitBootServicesCallback,
                  NULL,
                  &gEfiEventReadyToBootGuid,
                  &mReadyToBootEvent
                  );
  if (EFI_ERROR (Status)) {
    gBS->UninstallMultipleProtocolInterfaces (
           ImageHandle,
           &gEfiDriverBindingProtocolGuid,
           &gUefiMemDumpDriverBinding,
           NULL
           );
    return Status;
  }

  return EFI_SUCCESS;
}

VOID
EFIAPI
MemDumpCallback (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  EFI_STATUS  Status;

  if (mDumpTriggered) {
    return;
  }

  mDumpTriggered = TRUE;
  Status         = RunMemoryDump (mImageHandle);
  if (EFI_ERROR (Status)) {
    DUMP_LOG_ERR ("RunMemoryDump failed: %r\n", Status);
  } else {
    DUMP_LOG_INFO ("RunMemoryDump succeeded.\n");
  }
}

EFI_STATUS
EFIAPI
UefiMemDumpDriverBindingSupported (
  IN EFI_DRIVER_BINDING_PROTOCOL  *This,
  IN EFI_HANDLE                   ControllerHandle,
  IN EFI_DEVICE_PATH_PROTOCOL     *RemainingDevicePath OPTIONAL
  )
{
  return EFI_UNSUPPORTED;
}

EFI_STATUS
EFIAPI
UefiMemDumpDriverBindingStart (
  IN EFI_DRIVER_BINDING_PROTOCOL  *This,
  IN EFI_HANDLE                   ControllerHandle,
  IN EFI_DEVICE_PATH_PROTOCOL     *RemainingDevicePath OPTIONAL
  )
{
  return EFI_UNSUPPORTED;
}

EFI_STATUS
EFIAPI
UefiMemDumpDriverBindingStop (
  IN EFI_DRIVER_BINDING_PROTOCOL  *This,
  IN EFI_HANDLE                   ControllerHandle,
  IN UINTN                        NumberOfChildren,
  IN EFI_HANDLE                   *ChildHandleBuffer OPTIONAL
  )
{
  return EFI_UNSUPPORTED;
}
