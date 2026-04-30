/** @file
  UEFI memory dump application declarations.
**/

#ifndef __UEFI_MEM_DUMP_H__
#define __UEFI_MEM_DUMP_H__

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/SimpleFileSystem.h>

#define CHUNK_SIZE     ((UINTN)0x08000000)     // 128 MB
#define MAX_FILE_SIZE  ((UINTN)0xFF000000ULL)  // Keep margin below FAT32 hard limit

typedef struct {
  UINT32                Type;
  EFI_PHYSICAL_ADDRESS  StartAddress;
  EFI_PHYSICAL_ADDRESS  EndAddress;
  EFI_MEMORY_DESCRIPTOR *Descriptor;
  CONST CHAR16          *MemoryTypeString;
} REGION;

#endif
