"""Detect inline or trampoline hooks in EFI service-table targets."""

import json
import struct
from pathlib import Path

try:
    import capstone as cpt
except ModuleNotFoundError as exc:  # pragma: no cover - dependency guard
    raise ImportError(
        "The 'capstone' package is required for InlineHookingDetection. "
        "Install it with 'pip install \"capstone>=5.0.7,<6\"'."
    ) from exc

from uefi_dump_analysis.utilities import constants as cs
from uefi_dump_analysis.utilities import memory_utils as mu
from uefi_dump_analysis.utilities import parsing_utils as pu

MAX_HOPS = 3
INSTRUCTIONS_PER_HOP = 20
BYTES_PER_INSTRUCTION_BUDGET = 16
ENTRY_TRANSFER_WINDOW = 6

CONTROL_FLOW_MNEMONICS = {"jmp", "call"}
PE_DOS_SIGNATURE = b"MZ"
PE_NT_SIGNATURE = b"PE\x00\x00"
PE32_MAGIC = 0x10B
PE32_PLUS_MAGIC = 0x20B
IMAGE_SCN_MEM_EXECUTE = 0x20000000
SECTION_HEADER_SIZE = 40
MAX_SECTION_COUNT = 256
ZERO_EXTENDED_32BIT_REGS = {
    "eax",
    "ebx",
    "ecx",
    "edx",
    "esi",
    "edi",
    "esp",
    "ebp",
    "r8d",
    "r9d",
    "r10d",
    "r11d",
    "r12d",
    "r13d",
    "r14d",
    "r15d",
}

REG_ALIAS_TO_64 = {
    "al": "rax",
    "ah": "rax",
    "ax": "rax",
    "eax": "rax",
    "bl": "rbx",
    "bh": "rbx",
    "bx": "rbx",
    "ebx": "rbx",
    "cl": "rcx",
    "ch": "rcx",
    "cx": "rcx",
    "ecx": "rcx",
    "dl": "rdx",
    "dh": "rdx",
    "dx": "rdx",
    "edx": "rdx",
    "sil": "rsi",
    "si": "rsi",
    "esi": "rsi",
    "dil": "rdi",
    "di": "rdi",
    "edi": "rdi",
    "bpl": "rbp",
    "bp": "rbp",
    "ebp": "rbp",
    "spl": "rsp",
    "sp": "rsp",
    "esp": "rsp",
}


def _canonical_reg_name(reg_name):
    """Normalize Capstone register names to their 64-bit canonical form."""
    reg_name = reg_name.lower()
    if reg_name in REG_ALIAS_TO_64:
        return REG_ALIAS_TO_64[reg_name]

    if reg_name.startswith("r") and reg_name.endswith(("d", "w", "b")):
        # r8d -> r8, r10w -> r10, r15b -> r15
        return reg_name[:-1]

    return reg_name


def _find_identity_for_address(address, images):
    """Return the carved image identity that contains ``address``."""
    if address is None:
        return None

    for start, end, identity in images:
        if start <= address < end:
            return identity
    return None


def _find_image_for_address(address, images):
    """Return the full carved image tuple that contains ``address``."""
    if address is None:
        return None

    for image in images:
        start, end, _ = image
        if start <= address < end:
            return image
    return None


def _image_key(image_tuple):
    """Build a stable dictionary key for an image tuple."""
    start, end, identity = image_tuple
    return (start, end, str(identity))


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


def _parse_json_integer(value, field_name, record_index):
    """Parse an integer field from carving metadata."""
    if isinstance(value, bool):
        raise ValueError(f"record {record_index}: {field_name} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as exc:
            raise ValueError(
                f"record {record_index}: {field_name} must be an integer"
            ) from exc
    raise ValueError(f"record {record_index}: {field_name} must be an integer")


def _load_images_from_json(images_json_path):
    """Load image ranges from ``uefi_image_carving`` metadata."""
    path = Path(images_json_path)
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    if not isinstance(payload, list):
        raise ValueError(f"{path}: expected a JSON list of image records")

    images = []
    for index, record in enumerate(payload, start=1):
        if not isinstance(record, dict):
            raise ValueError(f"{path}: record {index} must be a JSON object")

        image_base = _parse_json_integer(record.get("image_base"), "image_base", index)
        if record.get("image_end") is not None:
            image_end = _parse_json_integer(record.get("image_end"), "image_end", index)
        elif record.get("image_size") is not None:
            image_size = _parse_json_integer(record.get("image_size"), "image_size", index)
            image_end = image_base + image_size
        else:
            raise ValueError(f"{path}: record {index} must include image_end or image_size")

        if image_end <= image_base:
            raise ValueError(f"{path}: record {index} has an invalid image range")

        identity = record.get("identity") or "unknown"
        images.append((image_base, image_end, str(identity)))

    return images


def _parse_pe_executable_ranges_for_image(dump_data, translator, image_start, image_end):
    """Parse executable PE section ranges for one carved image."""
    def _result(status, **overrides):
        """Build a uniform parser result payload."""
        result = {
            "status": status,
            "exec_ranges": [],
            "header_image_base": None,
            "header_base_matches_runtime": None,
            "header_size_of_image": None,
            "header_size_matches_runtime": None,
            "entry_point_rva": None,
            "entry_point_runtime": None,
            "entry_point_in_range": None,
            "invalid_exec_sections": 0,
            "pe_image_matches_record": False,
        }
        result.update(overrides)
        return result

    runtime_size = image_end - image_start
    if runtime_size < 0x100:
        return _result("too-small")

    initial_read_size = min(runtime_size, 0x1000)
    header_bytes = mu.read_runtime_bytes(
        dump_data, translator, image_start, initial_read_size, pad=False
    )
    if not header_bytes or len(header_bytes) < 0x40:
        return _result("header-read-failed")

    if header_bytes[:2] != PE_DOS_SIGNATURE:
        return _result("non-pe-signature")

    e_lfanew = struct.unpack_from("<I", header_bytes, 0x3C)[0]
    if e_lfanew + 24 > runtime_size:
        return _result("lfanew-out-of-range")

    min_nt_read = e_lfanew + 24
    if len(header_bytes) < min_nt_read:
        header_bytes = mu.read_runtime_bytes(
            dump_data, translator, image_start, min_nt_read, pad=False
        )
        if not header_bytes or len(header_bytes) < min_nt_read:
            return _result("nt-header-read-failed")

    if header_bytes[e_lfanew:e_lfanew + 4] != PE_NT_SIGNATURE:
        return _result("missing-pe-signature")

    number_of_sections = struct.unpack_from("<H", header_bytes, e_lfanew + 6)[0]
    size_of_optional_header = struct.unpack_from("<H", header_bytes, e_lfanew + 20)[0]
    if number_of_sections == 0 or number_of_sections > MAX_SECTION_COUNT:
        return _result("invalid-section-count")

    optional_header_offset = e_lfanew + 24
    required_optional_size = optional_header_offset + size_of_optional_header
    if required_optional_size > runtime_size:
        return _result("optional-header-out-of-range")

    section_table_offset = required_optional_size
    section_table_size = number_of_sections * SECTION_HEADER_SIZE
    required_total_size = section_table_offset + section_table_size
    if required_total_size > runtime_size:
        return _result("section-table-out-of-range")

    if len(header_bytes) < required_total_size:
        header_bytes = mu.read_runtime_bytes(
            dump_data, translator, image_start, required_total_size, pad=False
        )
        if not header_bytes or len(header_bytes) < required_total_size:
            return _result("section-table-read-failed")

    optional_magic = struct.unpack_from("<H", header_bytes, optional_header_offset)[0]
    if optional_magic == PE32_PLUS_MAGIC:
        header_image_base = struct.unpack_from(
            "<Q", header_bytes, optional_header_offset + 24
        )[0]
    elif optional_magic == PE32_MAGIC:
        header_image_base = struct.unpack_from(
            "<I", header_bytes, optional_header_offset + 28
        )[0]
    else:
        return _result("unsupported-optional-magic")

    entry_point_rva = struct.unpack_from("<I", header_bytes, optional_header_offset + 16)[0]
    entry_point_runtime = image_start + entry_point_rva
    entry_point_in_range = image_start <= entry_point_runtime < image_end

    header_size_of_image = struct.unpack_from(
        "<I", header_bytes, optional_header_offset + 56
    )[0]
    runtime_image_size = image_end - image_start
    header_size_matches_runtime = header_size_of_image == runtime_image_size
    header_base_matches_runtime = header_image_base == image_start

    exec_ranges = []
    invalid_exec_sections = 0
    for section_index in range(number_of_sections):
        section_offset = section_table_offset + (section_index * SECTION_HEADER_SIZE)
        characteristics = struct.unpack_from("<I", header_bytes, section_offset + 36)[0]
        if (characteristics & IMAGE_SCN_MEM_EXECUTE) == 0:
            continue

        virtual_size = struct.unpack_from("<I", header_bytes, section_offset + 8)[0]
        virtual_address = struct.unpack_from("<I", header_bytes, section_offset + 12)[0]
        size_of_raw_data = struct.unpack_from("<I", header_bytes, section_offset + 16)[0]
        section_span = max(virtual_size, size_of_raw_data)
        if section_span == 0:
            continue

        section_start = image_start + virtual_address
        section_end = section_start + section_span
        if section_start < image_start or section_end > image_end or section_end <= section_start:
            invalid_exec_sections += 1
            continue
        exec_ranges.append((section_start, section_end))

    common = {
        "exec_ranges": exec_ranges,
        "header_image_base": header_image_base,
        "header_base_matches_runtime": header_base_matches_runtime,
        "header_size_of_image": header_size_of_image,
        "header_size_matches_runtime": header_size_matches_runtime,
        "entry_point_rva": entry_point_rva,
        "entry_point_runtime": entry_point_runtime,
        "entry_point_in_range": entry_point_in_range,
        "invalid_exec_sections": invalid_exec_sections,
    }

    if not header_base_matches_runtime:
        return _result("header-base-mismatch", **common)
    if not header_size_matches_runtime:
        return _result("header-size-mismatch", **common)
    if not entry_point_in_range:
        return _result("entry-point-out-of-range", **common)
    if invalid_exec_sections > 0:
        return _result("exec-section-out-of-range", **common)
    if not exec_ranges:
        return _result("no-executable-sections", **common)

    return _result("ok", pe_image_matches_record=True, **common)


def _build_executable_section_map(dump_data, translator, images):
    """Build executable-section metadata for every carved image."""
    image_map = {}
    executable_ranges = []

    for image_tuple in images:
        image_start, image_end, _ = image_tuple
        parsed = _parse_pe_executable_ranges_for_image(
            dump_data, translator, image_start, image_end
        )
        image_map[_image_key(image_tuple)] = parsed
        for range_start, range_end in parsed["exec_ranges"]:
            executable_ranges.append((range_start, range_end))

    return image_map, executable_ranges


def _build_exec_debug_dump(images, executable_map):
    """Render summary debug output for executable-section parsing."""
    lines = []
    strict_match = 0
    strict_fail = 0
    parse_failed = 0
    base_match = 0
    base_mismatch = 0
    size_match = 0
    size_mismatch = 0
    entry_in_range = 0
    entry_out_of_range = 0
    no_executable_sections = 0
    invalid_sections = 0

    parse_failure_statuses = {
        "too-small",
        "header-read-failed",
        "non-pe-signature",
        "lfanew-out-of-range",
        "nt-header-read-failed",
        "missing-pe-signature",
        "invalid-section-count",
        "optional-header-out-of-range",
        "section-table-out-of-range",
        "section-table-read-failed",
        "unsupported-optional-magic",
    }

    for image_tuple in images:
        metadata = executable_map.get(_image_key(image_tuple), {})
        status = metadata.get("status")
        if status == "ok" and metadata.get("pe_image_matches_record") is True:
            strict_match += 1
        else:
            strict_fail += 1
        if status in parse_failure_statuses:
            parse_failed += 1
        if status == "no-executable-sections":
            no_executable_sections += 1

        if metadata.get("header_base_matches_runtime") is True:
            base_match += 1
        elif metadata.get("header_base_matches_runtime") is False:
            base_mismatch += 1

        if metadata.get("header_size_matches_runtime") is True:
            size_match += 1
        elif metadata.get("header_size_matches_runtime") is False:
            size_mismatch += 1

        if metadata.get("entry_point_in_range") is True:
            entry_in_range += 1
        elif metadata.get("entry_point_in_range") is False:
            entry_out_of_range += 1

        invalid_sections += metadata.get("invalid_exec_sections", 0)

    lines.append(
        "[debug] PE/image strict-match summary: "
        f"strict_match={strict_match} strict_fail={strict_fail} parse_failed={parse_failed} "
        f"header_base_match={base_match} header_base_mismatch={base_mismatch} "
        f"header_size_match={size_match} header_size_mismatch={size_mismatch} "
        f"entry_point_in_range={entry_in_range} entry_point_out_of_range={entry_out_of_range} "
        f"no_executable_sections={no_executable_sections} invalid_exec_sections={invalid_sections}"
    )
    return "\n".join(lines)


def _is_address_executable(address, images, executable_map):
    """Return whether ``address`` falls inside an executable range of its image."""
    image_tuple = _find_image_for_address(address, images)
    if image_tuple is None:
        return None

    metadata = executable_map.get(_image_key(image_tuple))
    if not metadata:
        return None

    if metadata.get("pe_image_matches_record") is not True:
        return None

    exec_ranges = metadata.get("exec_ranges", [])
    if not exec_ranges:
        return None

    for range_start, range_end in exec_ranges:
        if range_start <= address < range_end:
            return True
    return False


def _resolve_memory_operand_address(instruction, mem_operand, registers):
    """Resolve a memory operand into an effective runtime address when possible."""
    base_value = 0

    if mem_operand.base != 0:
        base_reg_name = _canonical_reg_name(instruction.reg_name(mem_operand.base))
        if base_reg_name == "rip":
            base_value = instruction.address + instruction.size
        else:
            base_value = registers.get(base_reg_name)
            if base_value is None:
                return None

    index_value = 0
    if mem_operand.index != 0:
        index_reg_name = _canonical_reg_name(instruction.reg_name(mem_operand.index))
        index_reg_value = registers.get(index_reg_name)
        if index_reg_value is None:
            return None
        index_value = index_reg_value * mem_operand.scale

    return (base_value + index_value + mem_operand.disp) & 0xFFFFFFFFFFFFFFFF


def _read_qword_runtime(dump_data, translator, runtime_address):
    """Read one runtime 64-bit value through the shared translator helper."""
    data = mu.read_runtime_bytes(dump_data, translator, runtime_address, 8, pad=False)
    if data is None or len(data) < 8:
        return None
    return struct.unpack("<Q", data)[0]


def _resolve_control_target(instruction, registers, dump_data, translator):
    """Resolve the target of a control-transfer instruction."""
    if not instruction.operands:
        return None, "no-operands"

    operand = instruction.operands[0]

    if operand.type == cpt.CS_OP_IMM:
        return operand.imm & 0xFFFFFFFFFFFFFFFF, "immediate"

    if operand.type == cpt.CS_OP_REG:
        reg_name = _canonical_reg_name(instruction.reg_name(operand.reg))
        return registers.get(reg_name), f"register:{reg_name}"

    if operand.type == cpt.CS_OP_MEM:
        pointer_address = _resolve_memory_operand_address(instruction, operand.mem, registers)
        if pointer_address is None:
            return None, "memory-unresolved"
        value = _read_qword_runtime(dump_data, translator, pointer_address)
        if value is None:
            return None, f"memory-read-failed:0x{pointer_address:016X}"
        return value, f"memory:0x{pointer_address:016X}"

    return None, "unsupported-operand"


def _update_register_state(instruction, registers, dump_data, translator):
    """Track simple register state needed for local control-flow resolution."""
    mnemonic = instruction.mnemonic
    operands = instruction.operands

    if mnemonic == "xor" and len(operands) == 2:
        if operands[0].type == cpt.CS_OP_REG and operands[1].type == cpt.CS_OP_REG:
            left = _canonical_reg_name(instruction.reg_name(operands[0].reg))
            right = _canonical_reg_name(instruction.reg_name(operands[1].reg))
            if left == right:
                registers[left] = 0
        return

    if mnemonic not in {"mov", "lea"} or len(operands) != 2:
        return

    dst, src = operands[0], operands[1]
    if dst.type != cpt.CS_OP_REG:
        return

    dst_raw = instruction.reg_name(dst.reg).lower()
    dst_reg = _canonical_reg_name(dst_raw)
    resolved = None

    if mnemonic == "lea" and src.type == cpt.CS_OP_MEM:
        resolved = _resolve_memory_operand_address(instruction, src.mem, registers)
    elif src.type == cpt.CS_OP_IMM:
        resolved = src.imm & 0xFFFFFFFFFFFFFFFF
    elif src.type == cpt.CS_OP_REG:
        src_reg = _canonical_reg_name(instruction.reg_name(src.reg))
        resolved = registers.get(src_reg)
    elif src.type == cpt.CS_OP_MEM:
        pointer_address = _resolve_memory_operand_address(instruction, src.mem, registers)
        if pointer_address is not None:
            resolved = _read_qword_runtime(dump_data, translator, pointer_address)

    if resolved is None:
        return

    if dst_raw in ZERO_EXTENDED_32BIT_REGS:
        resolved &= 0xFFFFFFFF

    registers[dst_reg] = resolved


def _is_suspicious_transfer(
    mnemonic,
    instruction_index,
    source_identity,
    target_address,
    target_identity,
    target_is_executable,
):
    """Apply the module's entry-transfer heuristics to one branch or call event."""
    # Focus on entry redirections to reduce noise.
    if instruction_index > ENTRY_TRANSFER_WINDOW:
        return False, ""

    if target_address is None:
        if mnemonic == "jmp":
            return True, "unresolved jump target near function entry"
        return False, ""

    if mnemonic == "jmp":
        if target_identity is None:
            return True, "entry jump targets unknown address"
        if target_is_executable is False:
            return True, "entry jump targets non-executable address"
        if source_identity and str(target_identity) != str(source_identity):
            return True, "entry jump leaves source image"

    if mnemonic == "call":
        if instruction_index <= 2:
            if target_identity is None:
                return True, "early call targets unknown address"
            if target_is_executable is False:
                return True, "early call targets non-executable address"

    return False, ""


def disassemble_code(
    dump_data,
    translator,
    start_address,
    images,
    executable_map,
    max_hops=MAX_HOPS,
    instructions_per_hop=INSTRUCTIONS_PER_HOP,
):
    """Disassemble from a service entrypoint and record suspicious transfers."""
    all_hops = []
    transfer_events = []
    current_address = start_address
    visited_addresses = set()
    registers = {}

    md = cpt.Cs(cpt.CS_ARCH_X86, cpt.CS_MODE_64)
    md.detail = True

    source_identity = _find_identity_for_address(start_address, images)

    for _ in range(max_hops):
        if current_address in visited_addresses:
            break
        visited_addresses.add(current_address)

        read_size = instructions_per_hop * BYTES_PER_INSTRUCTION_BUDGET
        code_bytes = mu.read_runtime_bytes(dump_data, translator, current_address, read_size, pad=False)
        if not code_bytes:
            break

        instructions = list(md.disasm(code_bytes, current_address))
        if not instructions:
            break

        hop_instructions = []
        next_address = None

        for instruction_index, instruction in enumerate(instructions[:instructions_per_hop]):
            hop_instructions.append((instruction.address, instruction.mnemonic, instruction.op_str))

            if instruction.mnemonic in CONTROL_FLOW_MNEMONICS:
                target_address, resolution_source = _resolve_control_target(
                    instruction, registers, dump_data, translator
                )
                target_identity = _find_identity_for_address(target_address, images)
                target_is_executable = _is_address_executable(
                    target_address, images, executable_map
                )
                suspicious, reason = _is_suspicious_transfer(
                    instruction.mnemonic,
                    instruction_index,
                    source_identity,
                    target_address,
                    target_identity,
                    target_is_executable,
                )
                transfer_events.append(
                    {
                        "instruction_address": instruction.address,
                        "mnemonic": instruction.mnemonic,
                        "op_str": instruction.op_str,
                        "target_address": target_address,
                        "target_identity": target_identity,
                        "target_is_executable": target_is_executable,
                        "resolution_source": resolution_source,
                        "suspicious": suspicious,
                        "reason": reason,
                    }
                )

                if next_address is None and instruction.mnemonic == "jmp" and target_address is not None:
                    next_address = target_address

            _update_register_state(instruction, registers, dump_data, translator)

        all_hops.append(hop_instructions)
        if next_address is None:
            break
        current_address = next_address

    return all_hops, transfer_events


def scan_for_hooks(dump_data, translator, function_pointers, images, executable_map):
    """Scan one set of service-table function pointers for inline hooks."""
    hooks = []

    for function_name, start_address in function_pointers.items():
        if start_address == 0:
            continue

        source_identity = _find_identity_for_address(start_address, images)
        source_is_executable = _is_address_executable(start_address, images, executable_map)

        if source_is_executable is False:
            hooks.append(
                {
                    "function_name": function_name,
                    "start_address": start_address,
                    "hops": [],
                    "transfers": [
                        {
                            "instruction_address": start_address,
                            "mnemonic": "<entry>",
                            "op_str": "<table-pointer>",
                            "target_address": start_address,
                            "target_identity": source_identity,
                            "target_is_executable": False,
                            "resolution_source": "service-table-pointer",
                            "suspicious": True,
                            "reason": "function pointer is not inside an executable section",
                        }
                    ],
                    "source_identity": source_identity or "<unknown>",
                }
            )
            continue

        hops, transfers = disassemble_code(
            dump_data, translator, start_address, images, executable_map
        )
        suspicious_transfers = [event for event in transfers if event["suspicious"]]

        if suspicious_transfers:
            hooks.append(
                {
                    "function_name": function_name,
                    "start_address": start_address,
                    "hops": hops,
                    "transfers": suspicious_transfers,
                    "source_identity": _find_identity_for_address(start_address, images) or "<unknown>",
                }
            )

    return hooks


def output_results(hooks, output_file=None):
    """Render hook findings and optionally append them to a report file."""
    lines = []

    if not hooks:
        lines.append("No functions with valid hooks found.")
    else:
        for hook in hooks:
            function_name = hook["function_name"]
            start_address = hook["start_address"]
            source_identity = hook["source_identity"]

            for transfer in hook["transfers"]:
                target_address = transfer["target_address"]
                target_identity = transfer["target_identity"] or "<unknown>"
                reason = transfer["reason"]

                lines.append("*" * 72)
                lines.append("Hook type: Inline/Trampoline")
                lines.append(f"Function: {function_name} at {start_address:#x}")
                lines.append(f"Function module: {source_identity}")
                if target_address is None:
                    lines.append("Hook address: <unresolved>")
                else:
                    lines.append(f"Hook address: {target_address:#x}")
                lines.append(f"Hooking module: {target_identity}")
                if transfer["target_is_executable"] is True:
                    lines.append("Hook address is executable: yes")
                elif transfer["target_is_executable"] is False:
                    lines.append("Hook address is executable: no")
                else:
                    lines.append("Hook address is executable: unknown")
                lines.append(
                    f"Trigger instruction: {transfer['instruction_address']:#x} "
                    f"{transfer['mnemonic']} {transfer['op_str']}"
                )
                lines.append(f"Resolution source: {transfer['resolution_source']}")
                lines.append(f"Reason: {reason}")
                lines.append("")

                for hop_index, hop_instructions in enumerate(hook["hops"]):
                    lines.append(f"Disassembly({hop_index}):")
                    for address, mnemonic, op_str in hop_instructions:
                        lines.append(f"{address:#x} {mnemonic:<16} {op_str}")
                    lines.append("")

    output_text = "\n".join(lines) + "\n"
    print(output_text)

    if output_file:
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("a", encoding="utf-8") as handle:
            handle.write(output_text)


def _analyze_table_set(
    dump_data,
    translator,
    images,
    executable_map,
    signature,
    table_size,
    function_names,
    require_valid_crc=False,
):
    """Analyze one EFI table class and return any suspicious hook findings."""
    hooks = []
    tables = pu.find_services_tables(dump_data, signature, table_size)
    if require_valid_crc:
        tables = [entry for entry in tables if entry[1].get("CRC32", 0) != 0]

    for table_data, _ in tables:
        function_pointers = pu.parse_function_pointers(table_data, function_names)
        hooks.extend(
            scan_for_hooks(
                dump_data, translator, function_pointers, images, executable_map
            )
        )
    return hooks


def run(args) -> None:
    """Execute inline-hook detection for the requested EFI service tables."""
    dump_data = mu.open_memory_dump(args.f)
    try:
        output_file = args.o
        memory_map_path = getattr(args, "memory_map", None)
        images_json_path = getattr(args, "images_json", None)
        require_valid_crc = bool(getattr(args, "require_valid_crc", False))

        if not memory_map_path:
            print(
                "[warning] -memory_map was not provided. Runtime-to-file translation falls back "
                "to identity mapping and may be inaccurate for non-identity dumps."
            )

        translator = mu.build_address_translator(dump_data, memory_map_path=memory_map_path)
        if images_json_path:
            try:
                images = _load_images_from_json(images_json_path)
            except (OSError, ValueError) as exc:
                raise SystemExit(
                    f"error: unable to load -images_json '{images_json_path}': {exc}"
                ) from exc
            print(f"[info] Loaded {len(images)} image records from {images_json_path}.")
        else:
            images = mu.extract_images(dump_data, memory_map_path=memory_map_path, quiet=True)
        executable_map, _ = _build_executable_section_map(dump_data, translator, images)

        if images and bool(getattr(args, "debug", False)):
            print(_build_image_debug_dump(images))
            print(_build_exec_debug_dump(images, executable_map))

        hooks = []
        process_all_tables = not (
            args.bootservicestable or args.runtimeservicestable or args.dxeservicestable
        )

        if args.bootservicestable or process_all_tables:
            hooks.extend(
                _analyze_table_set(
                    dump_data,
                    translator,
                    images,
                    executable_map,
                    cs.EFI_BOOT_SERVICES_SIGNATURE,
                    cs.EFI_BOOT_SERVICES_SIZE,
                    cs.BOOT_FUNCTIONS,
                    require_valid_crc=require_valid_crc,
                )
            )

        if args.runtimeservicestable or process_all_tables:
            hooks.extend(
                _analyze_table_set(
                    dump_data,
                    translator,
                    images,
                    executable_map,
                    cs.EFI_RUNTIME_SERVICES_SIGNATURE,
                    cs.EFI_RUNTIME_SERVICES_SIZE,
                    cs.RUNTIME_FUNCTIONS,
                    require_valid_crc=require_valid_crc,
                )
            )

        if args.dxeservicestable or process_all_tables:
            hooks.extend(
                _analyze_table_set(
                    dump_data,
                    translator,
                    images,
                    executable_map,
                    cs.EFI_DXE_SERVICES_SIGNATURE,
                    cs.EFI_DXE_SERVICES_SIZE,
                    cs.DXE_FUNCTIONS,
                    require_valid_crc=require_valid_crc,
                )
            )

        output_results(hooks, output_file)
    finally:
        dump_data.close()


plugin_info = {
    "name": "Inline Hook Detection",
    "description": (
        "Analyze EFI Boot, Runtime, and DXE Services Tables from a memory dump "
        "to detect inline/trampoline redirection."
    ),
    "arguments": [
        {"name": "-f", "help": "Memory dump file", "required": True},
        {
            "name": "-memory_map",
            "help": (
                "Optional path to Memory_Map.txt. Improves runtime-address "
                "translation for non-identity dumps."
            ),
            "required": False,
        },
        {
            "name": "-images_json",
            "help": (
                "Optional images.json from uefi_image_carving for the same dump. "
                "Used as a loaded-image metadata cache; PE parsing and "
                "disassembly still read bytes from the dump."
            ),
            "required": False,
        },
        {
            "name": "-o",
            "help": "Optional report file. Results are always printed to stdout.",
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
            "help": "Print debug information (including loaded image and executable-range summaries).",
            "action": "store_true",
        },
    ],
}
