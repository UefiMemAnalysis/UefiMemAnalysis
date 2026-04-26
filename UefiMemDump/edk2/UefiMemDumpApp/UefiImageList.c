/** @file
  Implementation for loaded-image metadata collection and serialization.
**/

#include "UefiImageList.h"

LIST_ENTRY  gImageList;

STATIC
EFI_GUID *
DuplicateGuid (
  IN CONST EFI_GUID  *Guid
  )
{
  if (Guid == NULL) {
    return NULL;
  }

  return AllocateCopyPool (sizeof (EFI_GUID), Guid);
}

STATIC
CHAR16 *
CopyFilePathNodeString (
  IN EFI_DEVICE_PATH_PROTOCOL  *Node
  )
{
  FILEPATH_DEVICE_PATH  *FilePathNode;
  UINTN                  NodeSize;
  UINTN                  MaxChars;
  UINTN                  Length;
  CHAR16                *Copy;

  if (Node == NULL) {
    return NULL;
  }

  if ((DevicePathType (Node) != MEDIA_DEVICE_PATH) ||
      (DevicePathSubType (Node) != MEDIA_FILEPATH_DP))
  {
    return NULL;
  }

  FilePathNode = (FILEPATH_DEVICE_PATH *)Node;
  NodeSize     = DevicePathNodeLength (&FilePathNode->Header);
  if (NodeSize <= OFFSET_OF (FILEPATH_DEVICE_PATH, PathName)) {
    return NULL;
  }

  MaxChars = (NodeSize - OFFSET_OF (FILEPATH_DEVICE_PATH, PathName)) / sizeof (CHAR16);
  if (MaxChars == 0) {
    return NULL;
  }

  Length = 0;
  while ((Length < MaxChars) && (FilePathNode->PathName[Length] != L'\0')) {
    Length++;
  }

  if (Length == 0) {
    return NULL;
  }

  if (Length == MaxChars) {
    // Ensure room for our own NUL if firmware path node is not terminated.
    Length--;
    if (Length == 0) {
      return NULL;
    }
  }

  Copy = AllocateZeroPool ((Length + 1) * sizeof (CHAR16));
  if (Copy == NULL) {
    return NULL;
  }

  CopyMem (Copy, FilePathNode->PathName, Length * sizeof (CHAR16));
  Copy[Length] = L'\0';
  return Copy;
}

STATIC
VOID
ResolveIdentityFromFilePath (
  IN  EFI_DEVICE_PATH_PROTOCOL  *FilePath,
  OUT EFI_GUID                  **Guid,
  OUT CHAR16                    **Path
  )
{
  MEDIA_FW_VOL_FILEPATH_DEVICE_PATH  *FwNode;

  *Guid = NULL;
  *Path = NULL;

  if (FilePath == NULL) {
    return;
  }

  if ((DevicePathType (FilePath) == MEDIA_DEVICE_PATH) &&
      (DevicePathSubType (FilePath) == MEDIA_PIWG_FW_FILE_DP))
  {
    FwNode = (MEDIA_FW_VOL_FILEPATH_DEVICE_PATH *)FilePath;
    *Guid  = DuplicateGuid (&FwNode->FvFileName);
    return;
  }

  if ((DevicePathType (FilePath) == MEDIA_DEVICE_PATH) &&
      (DevicePathSubType (FilePath) == MEDIA_FILEPATH_DP))
  {
    *Path = CopyFilePathNodeString (FilePath);
  }
}

STATIC
VOID
AddImageToList (
  IN EFI_HANDLE                 DeviceHandle,
  IN EFI_LOADED_IMAGE_PROTOCOL  *LoadedImage,
  IN EFI_HANDLE                 AppImageHandle
  )
{
  UEFI_IMAGE_INFO             *Entry;
  EFI_STATUS                   Status;
  EFI_LOADED_IMAGE_PROTOCOL   *ParentImage;

  if (LoadedImage == NULL) {
    return;
  }

  Entry = AllocateZeroPool (sizeof (UEFI_IMAGE_INFO));
  if (Entry == NULL) {
    return;
  }

  Entry->LoadedImage = LoadedImage;
  Entry->ImageHandle = DeviceHandle;
  Entry->ImageBase   = LoadedImage->ImageBase;
  if (LoadedImage->ImageSize <= (MAX_UINTN - (UINTN)LoadedImage->ImageBase))
  {
    Entry->ImageEnd = (VOID *)((UINTN)LoadedImage->ImageBase + LoadedImage->ImageSize);
  } else {
    Entry->ImageEnd = (VOID *)MAX_UINTN;
  }

  ResolveIdentityFromFilePath ((EFI_DEVICE_PATH_PROTOCOL *)LoadedImage->FilePath, &Entry->Guid, &Entry->Path);

  if ((Entry->Guid == NULL) && (Entry->Path == NULL) && (LoadedImage->ParentHandle != NULL)) {
    ParentImage = NULL;
    Status      = gBS->OpenProtocol (
                         LoadedImage->ParentHandle,
                         &gEfiLoadedImageProtocolGuid,
                         (VOID **)&ParentImage,
                         AppImageHandle,
                         NULL,
                         EFI_OPEN_PROTOCOL_GET_PROTOCOL
                         );
    if (!EFI_ERROR (Status) && (ParentImage != NULL)) {
      ResolveIdentityFromFilePath ((EFI_DEVICE_PATH_PROTOCOL *)ParentImage->FilePath, &Entry->ParentGuid, &Entry->ParentPath);
    }
  }

  InsertTailList (&gImageList, &Entry->Link);
}

EFI_STATUS
CollectLoadedImages (
  IN EFI_HANDLE  AppImageHandle
  )
{
  EFI_STATUS                  Status;
  EFI_HANDLE                 *HandleBuffer;
  UINTN                       HandleCount;
  EFI_LOADED_IMAGE_PROTOCOL  *LoadedImage;
  UINTN                       Index;

  InitializeListHead (&gImageList);

  HandleBuffer = NULL;
  Status       = gBS->LocateHandleBuffer (
                        ByProtocol,
                        &gEfiLoadedImageProtocolGuid,
                        NULL,
                        &HandleCount,
                        &HandleBuffer
                        );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  for (Index = 0; Index < HandleCount; Index++) {
    LoadedImage = NULL;
    Status      = gBS->OpenProtocol (
                         HandleBuffer[Index],
                         &gEfiLoadedImageProtocolGuid,
                         (VOID **)&LoadedImage,
                         AppImageHandle,
                         NULL,
                         EFI_OPEN_PROTOCOL_GET_PROTOCOL
                         );
    if (EFI_ERROR (Status) || (LoadedImage == NULL)) {
      continue;
    }

    if (LoadedImage->SystemTable != gST) {
      continue;
    }

    AddImageToList (HandleBuffer[Index], LoadedImage, AppImageHandle);
  }

  FreePool (HandleBuffer);
  return EFI_SUCCESS;
}

EFI_STATUS
WriteImageListToFile (
  IN EFI_FILE_PROTOCOL  *ParentDir,
  IN CHAR16             *FileName
  )
{
  EFI_STATUS         Status;
  EFI_FILE_PROTOCOL *File;
  LIST_ENTRY        *Link;
  UEFI_IMAGE_INFO   *Entry;
  CHAR16             Line[512];
  UINTN              LineSize;
  UINTN              Index;

  if ((ParentDir == NULL) || (FileName == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  File = NULL;
  Status = ParentDir->Open (
                        ParentDir,
                        &File,
                        FileName,
                        EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE,
                        0
                        );
  if (!EFI_ERROR (Status)) {
    File->Delete (File);
    File = NULL;
  }

  Status = ParentDir->Open (
                        ParentDir,
                        &File,
                        FileName,
                        EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
                        0
                        );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = File->SetPosition (File, 0);
  if (EFI_ERROR (Status)) {
    File->Close (File);
    return Status;
  }

  Index = 0;
  for (Link = gImageList.ForwardLink; Link != &gImageList; Link = Link->ForwardLink, Index++) {
    Entry = BASE_CR (Link, UEFI_IMAGE_INFO, Link);

    if (Entry->Guid != NULL) {
      UnicodeSPrint (
        Line,
        sizeof (Line),
        L"[%u] Guid: %g  Base: %p  End: %p\n",
        (UINT32)Index,
        Entry->Guid,
        Entry->ImageBase,
        Entry->ImageEnd
        );
    } else if (Entry->Path != NULL) {
      UnicodeSPrint (
        Line,
        sizeof (Line),
        L"[%u] Path: %s  Base: %p  End: %p\n",
        (UINT32)Index,
        Entry->Path,
        Entry->ImageBase,
        Entry->ImageEnd
        );
    } else if (Entry->ParentGuid != NULL) {
      UnicodeSPrint (
        Line,
        sizeof (Line),
        L"[%u] ParentGuid: %g  Base: %p  End: %p\n",
        (UINT32)Index,
        Entry->ParentGuid,
        Entry->ImageBase,
        Entry->ImageEnd
        );
    } else if (Entry->ParentPath != NULL) {
      UnicodeSPrint (
        Line,
        sizeof (Line),
        L"[%u] ParentPath: %s  Base: %p  End: %p\n",
        (UINT32)Index,
        Entry->ParentPath,
        Entry->ImageBase,
        Entry->ImageEnd
        );
    } else {
      UnicodeSPrint (
        Line,
        sizeof (Line),
        L"[%u] (unknown)  Base: %p  End: %p\n",
        (UINT32)Index,
        Entry->ImageBase,
        Entry->ImageEnd
        );
    }

    LineSize = StrLen (Line) * sizeof (CHAR16);
    Status   = File->Write (File, &LineSize, Line);
    if (EFI_ERROR (Status)) {
      break;
    }
  }

  File->Flush (File);
  File->Close (File);
  return Status;
}

VOID
FreeImageList (
  VOID
  )
{
  LIST_ENTRY      *Link;
  LIST_ENTRY      *Next;
  UEFI_IMAGE_INFO *Entry;

  for (Link = gImageList.ForwardLink; Link != &gImageList; Link = Next) {
    Next  = Link->ForwardLink;
    Entry = BASE_CR (Link, UEFI_IMAGE_INFO, Link);

    if (Entry->Guid != NULL) {
      FreePool (Entry->Guid);
    }

    if (Entry->Path != NULL) {
      FreePool (Entry->Path);
    }

    if (Entry->ParentGuid != NULL) {
      FreePool (Entry->ParentGuid);
    }

    if (Entry->ParentPath != NULL) {
      FreePool (Entry->ParentPath);
    }

    RemoveEntryList (Link);
    FreePool (Entry);
  }
}
