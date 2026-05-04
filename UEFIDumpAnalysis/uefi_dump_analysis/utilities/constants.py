# Constants for Boot, Runtime, and DXE Services
EFI_BOOT_SERVICES_SIGNATURE = b'BOOTSERV'
EFI_RUNTIME_SERVICES_SIGNATURE = b'RUNTSERV'
EFI_DXE_SERVICES_SIGNATURE = b'DXE_SERV'

EFI_BOOT_SERVICES_SIZE = 376
EFI_RUNTIME_SERVICES_SIZE = 136
EFI_DXE_SERVICES_SIZE = 168

# Constants for image extraction
SIGNATURE = b'ldri'
IMAGE_REVISION_OFFSET = 40  # EFI_LOADED_IMAGE_PROTOCOL.Revision
SYSTEM_TABLE_OFFSET = 56  # EFI_LOADED_IMAGE_PROTOCOL.SystemTable
IMAGE_BASE_OFFSET = 104  # Offset of ImageBasePage within the structure
IMAGE_SIZE_OFFSET = 112  # Offset of ImageSize within EFI_LOADED_IMAGE_PROTOCOL inside the structure
GUID_OFFSET = 72  # Offset from the beginning of the signature to the pointer address
GUID_SIZE = 16  # Size of the GUID in bytes
EFI_LOADED_IMAGE_PROTOCOL_REVISION = 0x1000
EFI_SYSTEM_TABLE_SIGNATURE = 0x5453595320494249  # 'IBI SYST' in little-endian

TABLES_HEADER_SIZE = 24

# Device path constants
MEDIA_DEVICE_PATH = 0x04
MEDIA_FILEPATH_DP = 0x04
MEDIA_FW_VOL_FILEPATH_DP = 0x06
END_DEVICE_PATH_TYPE = 0x7F

# PE image constants
MAX_IMAGE_SIZE = 0x40000000  # 1 GiB safety bound to reduce false-positive "ldri" hits.
PE_DOS_SIGNATURE = b"MZ"
PE_NT_SIGNATURE = b"PE\x00\x00"
PE32_MAGIC = 0x10B
PE32_PLUS_MAGIC = 0x20B
PE_MIN_HEADER_SIZE = 0x40
PE_SIZE_TOLERANCE = 0x1000
IMAGE_SCN_MEM_EXECUTE = 0x20000000
SECTION_HEADER_SIZE = 40
MAX_SECTION_COUNT = 256

# Known GUIDs for filtering - now supports multiple GUIDs per function
WHITE_LIST_GUIDS = {
    # DXE Core
    "DXECore": ["D6A2CB7F-6A18-4E2F-B43B-9920A733700A"],
    # Runtime Services
    "GetTime": ["378D7B65-8DA9-4773-B6E4-A47826A833E1"],  # PcRtc
    "SetTime": ["378D7B65-8DA9-4773-B6E4-A47826A833E1"],
    "GetWakeupTime": ["378D7B65-8DA9-4773-B6E4-A47826A833E1"],
    "SetWakeupTime": ["378D7B65-8DA9-4773-B6E4-A47826A833E1"],
    "SetVirtualAddressMap": ["B601F8C4-43B7-4784-95B1-F4226CB40CEE"],  # RuntimeDxe
    "ConvertPointer": ["B601F8C4-43B7-4784-95B1-F4226CB40CEE"],
    "GetVariable": [
        "CBD2E4D5-7068-4FF5-B462-9822B4AD8D60",  # VariableRuntimeDxe (EDK II)
        "66EECF40-6312-4A1A-A83A-B3B2F8D8A71A",  # LenovoVariableDxe (Lenovo)
    ],
    "GetNextVariableName": [
       "CBD2E4D5-7068-4FF5-B462-9822B4AD8D60",  # VariableRuntimeDxe (EDK II)
       "66EECF40-6312-4A1A-A83A-B3B2F8D8A71A",  # LenovoVariableDxe (Lenovo)
    ],
    "SetVariable": [
        "CBD2E4D5-7068-4FF5-B462-9822B4AD8D60",  # VariableRuntimeDxe (EDK II)
        "8B778A74-C275-49D5-93ED-4D709A129CB1",  # AbtDxe (Lenovo)
    ],
    "QueryVariableInfo": [
        "CBD2E4D5-7068-4FF5-B462-9822B4AD8D60",  # VariableRuntimeDxe (EDK II)
        "66EECF40-6312-4A1A-A83A-B3B2F8D8A71A",  # LenovoVariableDxe (Lenovo)
    ],
    "GetNextHighMonotonicCount": ["AD608272-D07F-4964-801E-7BD3B7888652"],
    "ResetSystem": ["4B28E4C7-FF36-4E10-93CF-A82159E777C5"],
    "UpdateCapsule": ["42857F0A-13F2-4B21-8A23-53D3F714B840"],
    "QueryCapsuleCapabilities": ["42857F0A-13F2-4B21-8A23-53D3F714B840"],
    # Boot Services
    "GetNextMonotonicCount": ["AD608272-D07F-4964-801E-7BD3B7888652"],
    "CalculateCrc32": ["B601F8C4-43B7-4784-95B1-F4226CB40CEE"],
    # Lenovo-specific Boot Services hooks
    "CreateEvent": ["AB3E46F0-844B-456E-8911-5D4546172410"],      # EventCtrl
    "SignalEvent": ["AB3E46F0-844B-456E-8911-5D4546172410"],
    "CloseEvent": ["AB3E46F0-844B-456E-8911-5D4546172410"],
    "ExitBootServices": ["AB3E46F0-844B-456E-8911-5D4546172410"],
    "CreateEventEx": ["AB3E46F0-844B-456E-8911-5D4546172410"],
}

BOOT_FUNCTIONS = [
    "RaiseTPL", "RestoreTPL", "AllocatePages", "FreePages", "GetMemoryMap", "AllocatePool",
    "FreePool", "CreateEvent", "SetTimer", "WaitForEvent", "SignalEvent", "CloseEvent",
    "CheckEvent", "InstallProtocolInterface", "ReinstallProtocolInterface", "UninstallProtocolInterface",
    "HandleProtocol", "Reserved", "RegisterProtocolNotify", "LocateHandle", "LocateDevicePath",
    "InstallConfigurationTable", "LoadImage", "StartImage", "Exit", "UnloadImage", "ExitBootServices",
    "GetNextMonotonicCount", "Stall", "SetWatchdogTimer", "ConnectController", "DisconnectController",
    "OpenProtocol", "CloseProtocol", "OpenProtocolInformation", "ProtocolsPerHandle", "LocateHandleBuffer",
    "LocateProtocol", "InstallMultipleProtocolInterfaces", "UninstallMultipleProtocolInterfaces", "CalculateCrc32",
    "CopyMem", "SetMem", "CreateEventEx"
]

RUNTIME_FUNCTIONS = [
    "GetTime", "SetTime", "GetWakeupTime", "SetWakeupTime", "SetVirtualAddressMap", "ConvertPointer",
    "GetVariable", "GetNextVariableName", "SetVariable", "GetNextHighMonotonicCount", "ResetSystem",
    "UpdateCapsule", "QueryCapsuleCapabilities", "QueryVariableInfo"
]

DXE_FUNCTIONS = [
    "AddMemorySpace", "AllocateMemorySpace", "FreeMemorySpace", "RemoveMemorySpace",
    "GetMemorySpaceDescriptor", "SetMemorySpaceAttributes", "GetMemorySpaceMap", "AddIoSpace",
    "AllocateIoSpace", "FreeIoSpace", "RemoveIoSpace", "GetIoSpaceDescriptor", "GetIoSpaceMap",
    "Dispatch", "Schedule", "Trust", "ProcessFirmwareVolume", "SetMemorySpaceCapabilities"
]
