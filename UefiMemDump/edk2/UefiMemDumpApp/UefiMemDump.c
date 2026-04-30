/** @file
  UEFI memory dump application.

  The application dumps memory from the device it was launched from by writing:
  - ImageList.txt
  - Memory_Map.txt
  - dump*.bin

  Safety notes:
  - No interactive blocking on failure paths.
  - All resource ownership is explicit with single-exit cleanup.
  - MMIO/reserved/unusable regions are zero-filled to avoid unsafe reads.
**/

#include "UefiMemDump.h"
#include "UefiImageList.h"

#define DUMP_DIR_NAME              L"\\Dump"
#define DUMP_MEM_MAP_FILE_NAME     L"Memory_Map.txt"
#define DUMP_IMAGE_LIST_FILE_NAME  L"ImageList.txt"

#define APP_ENABLE_IMAGE_LIST      TRUE
#define APP_PRINT_PROGRESS         TRUE
#define APP_PROGRESS_STEP_PERCENT  5U

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
    Array[Index].Type             = Descriptor->Type;
    Array[Index].StartAddress     = Descriptor->PhysicalStart;
    Array[Index].Descriptor       = Descriptor;
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

  MemMapFile = NULL;
  Status     = ParentDir->Open (
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
  CHAR16  FileName[32];

  if ((DumpDirectory == NULL) || (DumpFile == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  UnicodeSPrint (FileName, sizeof (FileName), L"dump%u.bin", (UINT32)DumpFileIndex);
  return DumpDirectory->Open (
                          DumpDirectory,
                          DumpFile,
                          FileName,
                          EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
                          0
                          );
}

STATIC
EFI_STATUS
DumpEntireMemory (
  IN EFI_FILE_PROTOCOL  *DumpDirectory,
  IN REGION             *Regions,
  IN UINTN              RegionCount,
  IN UINTN              TotalMemorySize,
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
  UINT64                TotalWrittenBytes;
  UINTN                 NextProgress;

  if ((DumpDirectory == NULL) || (Regions == NULL) || (TotalMemorySize == 0)) {
    return EFI_INVALID_PARAMETER;
  }

  BatchBuffer = AllocatePool (CHUNK_SIZE);
  if (BatchBuffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  DumpFile               = NULL;
  DumpFileIndex          = 1;
  ProcessedInCurrentFile = 0;
  TotalWrittenBytes      = 0;
  NextProgress           = APP_PROGRESS_STEP_PERCENT;

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

    RegionSize = (UINTN)(Regions[Index].Descriptor->NumberOfPages * EFI_PAGE_SIZE);
    if (RegionSize == 0) {
      continue;
    }

    RegionStart  = Regions[Index].StartAddress;
    RegionOffset = 0;
    while (RegionOffset < RegionSize) {
      ChunkSize = RegionSize - RegionOffset;
      if (ChunkSize > CHUNK_SIZE) {
        ChunkSize = CHUNK_SIZE;
      }

      if (ShouldZeroFillRegion (RegionType)) {
        SetMem (BatchBuffer, ChunkSize, 0);
      } else {
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
          DumpFile->Flush (DumpFile);
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

        if (RequestedWrite == 0) {
          Status = EFI_DEVICE_ERROR;
          goto Exit;
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

        BufferOffset           += RequestedWrite;
        ProcessedInCurrentFile += RequestedWrite;
        TotalWrittenBytes      += RequestedWrite;

        if (APP_PRINT_PROGRESS && (TotalMemorySize != 0) && (NextProgress <= 100)) {
          UINTN  CurrentProgress;
          UINT64 Scaled;

          if (TotalWrittenBytes > (MAX_UINT64 / 100ULL)) {
            CurrentProgress = 100;
          } else {
            Scaled = TotalWrittenBytes * 100ULL;
            CurrentProgress = (UINTN)(Scaled / (UINT64)TotalMemorySize);
          }

          while ((CurrentProgress >= NextProgress) && (NextProgress <= 100)) {
            Print (L"\rDump progress: %u%%", (UINT32)NextProgress);
            NextProgress += APP_PROGRESS_STEP_PERCENT;
          }
        }
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

  if (APP_PRINT_PROGRESS && !EFI_ERROR (Status)) {
    Print (L"\rDump progress: 100%%\n");
  }

  return Status;
}

EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                         Status;
  EFI_LOADED_IMAGE_PROTOCOL          *AppLoadedImage;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL    *FileSystem;
  EFI_FILE_PROTOCOL                  *RootDir;
  EFI_FILE_PROTOCOL                  *DumpDir;
  EFI_MEMORY_DESCRIPTOR              *MemoryMap;
  UINTN                              MemoryMapSize;
  UINTN                              DescriptorSize;
  REGION                             *Regions;
  UINTN                              RegionCount;
  UINTN                              TotalMemorySize;
  BOOLEAN                            ExcludeConventional;
  BOOLEAN                            ExcludeReserved;

  AppLoadedImage      = NULL;
  FileSystem          = NULL;
  RootDir             = NULL;
  DumpDir             = NULL;
  MemoryMap           = NULL;
  MemoryMapSize       = 0;
  DescriptorSize      = 0;
  Regions             = NULL;
  RegionCount         = 0;
  ExcludeConventional = FALSE;
  ExcludeReserved     = FALSE;

  // Resolve the launch-device filesystem from this app's own loaded-image handle.
  Status = gBS->HandleProtocol (
                  ImageHandle,
                  &gEfiLoadedImageProtocolGuid,
                  (VOID **)&AppLoadedImage
                  );
  if (EFI_ERROR (Status) || (AppLoadedImage == NULL) || (AppLoadedImage->DeviceHandle == NULL)) {
    Print (L"UefiMemDump: failed to resolve loaded image protocol: %r\n", Status);
    goto Cleanup;
  }

  Status = gBS->HandleProtocol (
                  AppLoadedImage->DeviceHandle,
                  &gEfiSimpleFileSystemProtocolGuid,
                  (VOID **)&FileSystem
                  );
  if (EFI_ERROR (Status) || (FileSystem == NULL)) {
    Print (L"UefiMemDump: failed to locate file system on launch device: %r\n", Status);
    goto Cleanup;
  }

  Status = FileSystem->OpenVolume (FileSystem, &RootDir);
  if (EFI_ERROR (Status) || (RootDir == NULL)) {
    Print (L"UefiMemDump: failed to open root volume: %r\n", Status);
    goto Cleanup;
  }

  // Dump artifacts are always created under \Dump on the launch device.
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
    Print (L"UefiMemDump: failed to open/create dump directory: %r\n", Status);
    goto Cleanup;
  }

  Status = GetCurrentMemoryMap (&MemoryMap, &MemoryMapSize, &DescriptorSize);
  if (EFI_ERROR (Status)) {
    Print (L"UefiMemDump: GetCurrentMemoryMap failed: %r\n", Status);
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
    Print (L"UefiMemDump: invalid total dump size: 0x%lx\n", (UINT64)TotalMemorySize);
    goto Cleanup;
  }

  if (APP_ENABLE_IMAGE_LIST) {
    Status = CollectLoadedImages (ImageHandle);
    if (!EFI_ERROR (Status)) {
      Status = WriteImageListToFile (DumpDir, DUMP_IMAGE_LIST_FILE_NAME);
      if (EFI_ERROR (Status)) {
        Print (L"UefiMemDump: WriteImageListToFile failed: %r\n", Status);
      }

      FreeImageList ();
    } else {
      Print (L"UefiMemDump: CollectLoadedImages failed: %r\n", Status);
    }
  }

  Status = DumpMemoryMap (
             DumpDir,
             DUMP_MEM_MAP_FILE_NAME,
             MemoryMapSize,
             DescriptorSize,
             MemoryMap
             );
  if (EFI_ERROR (Status)) {
    Print (L"UefiMemDump: DumpMemoryMap failed: %r\n", Status);
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
    Print (L"UefiMemDump: CollectAndSortMemoryRanges failed: %r\n", Status);
    goto Cleanup;
  }

  Print (L"UefiMemDump: dumping 0x%lx bytes from %u regions.\n", (UINT64)TotalMemorySize, (UINT32)RegionCount);
  Status = DumpEntireMemory (
             DumpDir,
             Regions,
             RegionCount,
             TotalMemorySize,
             ExcludeConventional,
             ExcludeReserved
             );
  if (EFI_ERROR (Status)) {
    Print (L"UefiMemDump: DumpEntireMemory failed: %r\n", Status);
    goto Cleanup;
  }

  Print (L"UefiMemDump: dump completed successfully.\n");

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
