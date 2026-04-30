/** @file
  UEFI memory dump driver declarations.
**/

#ifndef __EFI_UEFI_MEM_DUMP_H__
#define __EFI_UEFI_MEM_DUMP_H__

#include <Uefi.h>
#include <Guid/EventGroup.h>
#include <Guid/FileInfo.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Protocol/BlockIo.h>
#include <Protocol/DevicePath.h>
#include <Protocol/DriverBinding.h>
#include <Protocol/SimpleFileSystem.h>

#include "DriverBinding.h"

#define MEM_DRIVER_VERSION  0x00000001
#define CHUNK_SIZE          ((UINTN)0x08000000)     // 128 MB
#define MAX_FILE_SIZE       ((UINTN)0xFFFFFFFFULL)  // FAT32 max file size

typedef struct {
  UINT32                Type;
  EFI_PHYSICAL_ADDRESS  StartAddress;
  EFI_PHYSICAL_ADDRESS  EndAddress;
  EFI_MEMORY_DESCRIPTOR *Descriptor;
  CONST CHAR16          *MemoryTypeString;
} REGION;

extern EFI_DRIVER_BINDING_PROTOCOL  gUefiMemDumpDriverBinding;

EFI_STATUS
EFIAPI
UefiMemDumpDriverEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  );

EFI_STATUS
EFIAPI
UefiMemDumpUnload (
  IN EFI_HANDLE  ImageHandle
  );

VOID
EFIAPI
MemDumpCallback (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  );

#endif
