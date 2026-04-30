#include "GuidParse.h"
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>


UINTN
HexCharToDecimal(
    IN CHAR16 Char
    )
{
    if (Char >= L'0' && Char <= L'9') {
        return (UINTN)(Char - L'0');
    } else if (Char >= L'a' && Char <= L'f') {
        return (UINTN)(Char - L'a' + HEX_BASE_10);
    } else if (Char >= L'A' && Char <= L'F') {
        return (UINTN)(Char - L'A' + HEX_BASE_10);
    } else {
        return 0;
    }
}

EFI_STATUS ConvertStrToGuid(IN CONST CHAR16 *String, OUT GUID *Guid)
{
    CONST CHAR16  *Walker;
    UINT8         TempValue;
    UINTN         Index;

    if (String == NULL) {
        return EFI_UNSUPPORTED;
    }

    Index = 0;
    Walker = String;
    Guid->Data1 = (UINT32)StrHexToUint64(Walker);

    Walker += GUID_HYPHEN_STEP1;
    Guid->Data2 = (UINT16)StrHexToUint64(Walker);

    Walker += GUID_HYPHEN_STEP2;
    Guid->Data3 = (UINT16)StrHexToUint64(Walker);

    Walker += GUID_HYPHEN_STEP2;
    while (Walker != NULL && *Walker != CHAR_NULL && Index < GUID_DATA4_SIZE) {
        if (*Walker == L'-') {
            Walker++;
        } else {
            TempValue = (UINT8)HexCharToDecimal(*Walker);
            TempValue = (UINT8)LShiftU64(TempValue, 4);
            Walker++;

            TempValue += (UINT8)HexCharToDecimal(*Walker);
            Walker++;

            Guid->Data4[Index] = TempValue;
            Index++;
        }
    }

    return EFI_SUCCESS;
}

BOOLEAN ParseGuidFromString(CONST CHAR16 *Str, EFI_GUID *Guid) {
        if (Str == NULL || Guid == NULL) return FALSE;
        EFI_STATUS Status = ConvertStrToGuid(Str, Guid);
        return (Status == EFI_SUCCESS);
}

CHAR16 EFIAPI
ToLower (
  IN CHAR16 Character
  )
{
  if (Character >= L'A' && Character <= L'Z') {
    return Character + (L'a' - L'A');
  }
  return (CHAR16)Character;
}

UINTN EFIAPI
GuidToPath (
  IN  EFI_GUID  *Guid,
  OUT CHAR16    *Buffer,
  IN  UINTN     BufferSize
  )
{
  CHAR16 *AsUtf16 = (CHAR16 *)Guid;
  UINTN   MaxLen = BufferSize - 1;
  UINTN   i;

  for (i = 0; i < MaxLen; i++) {
    if (AsUtf16[i] == L'\0') {
      break;
    }
  }

  if (i > 0) {
    BOOLEAN LooksLikePath = FALSE;

    for (UINTN j = 0; j < i; j++) {
      if (AsUtf16[j] == L'\\' || AsUtf16[j] == L'/') {
        LooksLikePath = TRUE;
        break;
      }
    }

    if (LooksLikePath) {
      CONST CHAR16 *KnownExts[] = { L".efi", L".dll", L".exe", L".bin" };
      BOOLEAN HasKnownExtension = FALSE;

      if (i >= EXTENSION_LENGTH) {
        CHAR16 Temp[EXTENSION_BUFFER_SIZE] = {0};
        for (UINTN j = 0; j < EXTENSION_LENGTH; j++) {
          Temp[j] = ToLower(AsUtf16[i - EXTENSION_LENGTH + j]);
        }

        for (UINTN k = 0; k < ARRAY_SIZE(KnownExts); k++) {
          if (StrCmp(Temp, KnownExts[k]) == 0) {
            HasKnownExtension = TRUE;
            break;
          }
        }
      }

      if (HasKnownExtension || i >= MINIMUM_PATH_LENGTH) {
        UINTN CopyLen = (i < BufferSize - 1) ? i : BufferSize - 1;
        for (UINTN c = 0; c < CopyLen; c++) {
          Buffer[c] = AsUtf16[c];
        }
        Buffer[CopyLen] = L'\0';
        return CopyLen;
      }
    }
  }

  Buffer[0] = L'\0';
  return 0;
}
