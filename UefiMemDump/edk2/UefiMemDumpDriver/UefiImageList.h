/** @file
  Loaded-image metadata collection helpers for UefiMemDump.

  Builds an in-memory list of loaded image identities (FV GUID or file path),
  runtime image ranges, and optional parent image identity.
**/

#pragma once
#ifndef __UEFI_IMAGE_LIST_H__
#define __UEFI_IMAGE_LIST_H__

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/DevicePath.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/SimpleFileSystem.h>

typedef struct {
  EFI_LOADED_IMAGE_PROTOCOL *LoadedImage;
  EFI_HANDLE                 ImageHandle;
  EFI_GUID                  *Guid;
  CHAR16                    *Path;
  EFI_GUID                  *ParentGuid;
  CHAR16                    *ParentPath;
  LIST_ENTRY                 Link;
  VOID                      *ImageBase;
  VOID                      *ImageEnd;
} UEFI_IMAGE_INFO;

extern LIST_ENTRY  gImageList;

EFI_STATUS
CollectLoadedImages (
  IN EFI_HANDLE  AppImageHandle
  );

EFI_STATUS
WriteImageListToFile (
  IN EFI_FILE_PROTOCOL  *ParentDir,
  IN CHAR16             *FileName
  );

VOID
FreeImageList (
  VOID
  );

#endif
