"""Detect suspicious EFI service-table pointers in a UEFI memory dump."""

from pathlib import Path

from uefi_dump_analysis.utilities import constants as cs
from uefi_dump_analysis.utilities import memory_utils as mu
from uefi_dump_analysis.utilities import parsing_utils as pu

DXE_CORE_GUID = "D6A2CB7F-6A18-4E2F-B43B-9920A733700A"

def _find_identity_for_address(address, images):
    """Return the carved image identity that contains ``address``."""
    for start, end, identity in images:
        if start <= address < end:
            return identity
    return None


def _build_image_debug_dump(images):
    """Render a debug table of loaded image ranges."""
    lines = []
    lines.append("[debug] Loaded image ranges:")
    lines.append(
        "[debug] index | start               | end                 | identity"
    )
    for index, (start, end, identity) in enumerate(sorted(images, key=lambda item: item[0]), start=1):
        lines.append(
            f"[debug] {index:5d} | 0x{start:016X} | 0x{end:016X} | {identity}"
        )
    return "\n".join(lines)


def _is_identity_whitelisted(function_name, identity):
    """Return ``True`` when a pointer target is expected for the given service."""
    if not identity:
        return False

    identity_upper = str(identity).upper()
    if identity_upper == DXE_CORE_GUID:
        return True

    allowed_guids = cs.WHITE_LIST_GUIDS.get(function_name, [])
    if isinstance(allowed_guids, str):
        allowed_guids = [allowed_guids]

    allowed_upper = {str(guid).upper() for guid in allowed_guids}
    return identity_upper in allowed_upper


def _classify_pointer(function_name, pointer_value, images):
    """Classify one service-table pointer as expected or suspicious."""
    if function_name == "Reserved":
        if pointer_value == 0:
            return False, ""
        return True, " <- suspicious (Reserved must be 0)"

    if pointer_value == 0:
        return True, " <- suspicious (NULL function pointer)"

    identity = _find_identity_for_address(pointer_value, images)
    if identity is None:
        return True, " <- suspicious (address outside known loaded images)"

    if _is_identity_whitelisted(function_name, identity):
        return False, ""

    if isinstance(identity, str) and (identity.startswith("\\") or identity.startswith("/")):
        return True, f" <- suspicious (points to image loaded from path {identity})"

    return True, f" <- suspicious (points to image {identity})"


def _format_table_results(table_name, tables_results, images):
    """Render the pointer-analysis results for one table class."""
    output = []
    for index, (function_pointers, table_info) in enumerate(tables_results, start=1):
        suspicious_count = 0

        output.append(f"{table_name} Table #{index}:")
        output.append("-" * 10)
        output.append(f"Offset in dump file: 0x{table_info['Pointer']:08X}")
        output.append(f"Signature {table_info['SignatureASCII']}")
        output.append(f"Revision: {table_info['Revision']} (Raw: 0x{table_info['RevisionHex']})")
        output.append(f"Header Size: {table_info['HeaderSize']} bytes")
        output.append(f"CRC32: 0x{table_info['CRC32']:08X}")
        output.append(f"Reserved: {table_info['Reserved']}")
        output.append("")
        output.append("Function Pointers:")

        for function_name, pointer_value in function_pointers.items():
            suspicious, annotation = _classify_pointer(function_name, pointer_value, images)
            if suspicious:
                suspicious_count += 1
            output.append(f"{function_name}: {pointer_value:016X}{annotation}")

        output.append("")
        output.append(f"Suspicious entries in table: {suspicious_count}")
        output.append("")
        output.append("=" * 50)
        output.append("")

    return "\n".join(output)


def _collect_table_analysis(
    dump_data,
    signature,
    table_size,
    function_names,
    require_valid_crc=False,
):
    """Locate candidate service tables and parse their function pointers."""
    tables = pu.find_services_tables(dump_data, signature, table_size)
    if require_valid_crc:
        tables = [entry for entry in tables if entry[1].get("CRC32", 0) != 0]

    analyzed = []
    for table_data, table_info in tables:
        function_pointers = pu.parse_function_pointers(table_data, function_names)
        analyzed.append((function_pointers, table_info))
    return analyzed


def _write_output(output_text, output_file) -> None:
    """Print results and optionally append them to ``output_file``."""
    print(output_text)
    if output_file:
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("a", encoding="utf-8") as handle:
            handle.write(output_text)


def run(args) -> None:
    """Execute pointer-hook detection for the requested EFI service tables."""
    dump_data = mu.open_memory_dump(args.f)
    try:
        memory_map_path = getattr(args, "memory_map", None)
        require_valid_crc = bool(getattr(args, "require_valid_crc", False))

        if not memory_map_path:
            print(
                "[warning] -memory_map was not provided. Address translation falls back to identity "
                "mapping and may be inaccurate for non-identity dumps."
            )

        images = mu.extract_images(
            dump_data,
            memory_map_path=memory_map_path,
            quiet=True,
        )

        if not images:
            print("[warning] No loaded images were extracted. Hook classification will be limited.")
        elif bool(getattr(args, "debug", False)):
            print(_build_image_debug_dump(images))

        process_all_tables = not (
            args.bootservicestable or args.runtimeservicestable or args.dxeservicestable
        )

        any_output = False

        if args.bootservicestable or process_all_tables:
            boot_tables = _collect_table_analysis(
                dump_data,
                cs.EFI_BOOT_SERVICES_SIGNATURE,
                cs.EFI_BOOT_SERVICES_SIZE,
                cs.BOOT_FUNCTIONS,
                require_valid_crc=require_valid_crc,
            )
            if boot_tables:
                output = _format_table_results("Boot Services", boot_tables, images)
                _write_output(output, args.o)
                any_output = True
            else:
                print("EFI Boot Services Table not found in the dump.")

        if args.runtimeservicestable or process_all_tables:
            runtime_tables = _collect_table_analysis(
                dump_data,
                cs.EFI_RUNTIME_SERVICES_SIGNATURE,
                cs.EFI_RUNTIME_SERVICES_SIZE,
                cs.RUNTIME_FUNCTIONS,
                require_valid_crc=require_valid_crc,
            )
            if runtime_tables:
                output = _format_table_results("Runtime Services", runtime_tables, images)
                _write_output(output, args.o)
                any_output = True
            else:
                print("EFI Runtime Services Table not found in the dump.")

        if args.dxeservicestable or process_all_tables:
            dxe_tables = _collect_table_analysis(
                dump_data,
                cs.EFI_DXE_SERVICES_SIGNATURE,
                cs.EFI_DXE_SERVICES_SIZE,
                cs.DXE_FUNCTIONS,
                require_valid_crc=require_valid_crc,
            )
            if dxe_tables:
                output = _format_table_results("DXE Services", dxe_tables, images)
                _write_output(output, args.o)
                any_output = True
            else:
                print("EFI DXE Services Table not found in the dump.")

        if not any_output:
            print("No service tables were analyzed.")
    finally:
        dump_data.close()


plugin_info = {
    "name": "Pointer Hook Detection",
    "description": (
        "Analyze EFI Boot, Runtime, and DXE Services Tables from a memory dump to detect "
        "suspicious function-pointer redirection."
    ),
    "arguments": [
        {"name": "-f", "help": "Memory dump file", "required": True},
        {
            "name": "-memory_map",
            "help": (
                "Optional path to Memory_Map.txt. Improves address translation for "
                "non-identity dumps."
            ),
            "required": False,
        },
        {
            "name": "-bootservicestable",
            "help": "Analyze only EFI Boot Services tables. If no table flag is set, all table classes are analyzed.",
            "action": "store_true",
        },
        {
            "name": "-runtimeservicestable",
            "help": "Analyze only EFI Runtime Services tables. If no table flag is set, all table classes are analyzed.",
            "action": "store_true",
        },
        {
            "name": "-dxeservicestable",
            "help": "Analyze only EFI DXE Services tables. If no table flag is set, all table classes are analyzed.",
            "action": "store_true",
        },
        {
            "name": "-require_valid_crc",
            "help": "Only analyze candidate tables whose header CRC32 field is non-zero.",
            "action": "store_true",
        },
        {
            "name": "-debug",
            "help": "Print debug information (including loaded image ranges).",
            "action": "store_true",
        },
        {
            "name": "-o",
            "help": "Optional report file. Results are always printed to stdout.",
            "required": False,
        },
    ],
}
