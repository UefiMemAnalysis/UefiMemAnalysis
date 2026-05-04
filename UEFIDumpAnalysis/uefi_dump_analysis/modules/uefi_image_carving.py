"""Carve loaded UEFI images and emit the associated metadata from memory dumps."""

import csv
import json
import os
import re
import struct
from dataclasses import dataclass
from typing import Any, Optional

from uefi_dump_analysis.utilities import constants as cs
from uefi_dump_analysis.utilities import memory_utils as mu

MIN_LOADED_IMAGE_READ_SIZE = cs.IMAGE_SIZE_OFFSET + 8


@dataclass(frozen=True)
class ImageRecord:
    struct_offset: int
    revision: int
    system_table_pointer: int
    system_table_signature_valid: bool
    image_base: int
    image_size: int
    image_end: int
    file_path_pointer: int
    identity: str = "unknown"


@dataclass(frozen=True)
class PeHeaderCandidate:
    offset: int
    image_base: int
    size_of_image: int


def _classify_loaded_image_candidate(data, signature_offset):
    """Validate one signature hit and return either a record or a rejection reason."""
    if signature_offset + MIN_LOADED_IMAGE_READ_SIZE > len(data):
        return None, "too_short"

    revision = struct.unpack_from("<I", data, signature_offset + cs.IMAGE_REVISION_OFFSET)[0]
    if revision != cs.EFI_LOADED_IMAGE_PROTOCOL_REVISION:
        return None, "bad_revision"

    system_table_pointer = mu.read_u64_le(data, signature_offset + cs.SYSTEM_TABLE_OFFSET)
    if system_table_pointer == 0:
        return None, "null_system_table_pointer"

    image_base = mu.read_u64_le(data, signature_offset + cs.IMAGE_BASE_OFFSET)
    image_size = mu.read_u64_le(data, signature_offset + cs.IMAGE_SIZE_OFFSET)
    file_path_ptr = mu.read_u64_le(data, signature_offset + cs.GUID_OFFSET)

    if image_base == 0 or image_size == 0:
        return None, "zero_base_or_size"
    if image_size > cs.MAX_IMAGE_SIZE:
        return None, "oversized_image"

    image_end = image_base + image_size
    if image_end <= image_base:
        return None, "wrapped_image_range"

    return (
        ImageRecord(
            struct_offset=signature_offset,
            revision=revision,
            system_table_pointer=system_table_pointer,
            system_table_signature_valid=False,
            image_base=image_base,
            image_size=image_size,
            image_end=image_end,
            file_path_pointer=file_path_ptr,
        ),
        None,
    )


def _looks_like_loaded_image(data, signature_offset):
    """Validate a potential ``LOADED_IMAGE_PRIVATE_DATA`` structure candidate."""
    record, _ = _classify_loaded_image_candidate(data, signature_offset)
    return record


def _decode_utf16_path(raw_bytes):
    """Decode a UTF-16 device-path payload into a printable filesystem path."""
    if not raw_bytes:
        return None

    if len(raw_bytes) % 2:
        raw_bytes = raw_bytes[:-1]

    text = raw_bytes.decode("utf-16-le", errors="ignore").split("\x00", 1)[0].strip()
    if text:
        return text
    return None


def _extract_identity_from_device_path(data, translator, pointer_address, max_bytes=1024):
    """Extract the best GUID or path identity from a device-path structure."""
    pointer_offset = translator.to_file_offset(pointer_address)
    if pointer_offset is None or pointer_offset + 4 > len(data):
        return "unknown"

    current = pointer_offset
    consumed = 0
    while consumed < max_bytes and current + 4 <= len(data):
        node_type, node_subtype, node_len = struct.unpack_from("<BBH", data, current)
        if node_len < 4:
            return "unknown"

        node_end = current + node_len
        if node_end > len(data):
            return "unknown"

        payload = data[current + 4:node_end]
        if node_type == cs.MEDIA_DEVICE_PATH:
            if node_subtype == cs.MEDIA_FW_VOL_FILEPATH_DP and len(payload) >= cs.GUID_SIZE:
                guid = mu.parse_guid(payload[:cs.GUID_SIZE])
                if guid and guid != "00000000-0000-0000-0000-000000000000":
                    return guid
            elif node_subtype == cs.MEDIA_FILEPATH_DP:
                path = _decode_utf16_path(payload)
                if path:
                    return path

        if node_type == cs.END_DEVICE_PATH_TYPE:
            break

        consumed += node_len
        current = node_end

    return "unknown"


def _sanitize_filename(value):
    """Convert an identity string into a filesystem-safe tag."""
    safe = value.replace("\\", "_").replace("/", "_").replace(":", "_").strip()
    return safe if safe else "unknown"


def _load_reference_image_list(image_list_path):
    """Parse a reference image list used for carving verification."""
    with open(image_list_path, "rb") as handle:
        raw = handle.read()
    try:
        text = raw.decode("utf-16")
    except UnicodeError:
        text = raw.decode("utf-16-le", errors="ignore")

    entries = []
    line_re = re.compile(
        r"\[(\d+)\]\s+(Guid|Path):\s*(.*?)\s+Base:\s*([0-9A-Fa-f]+)\s+End:\s*([0-9A-Fa-f]+)"
    )
    for line in text.splitlines():
        match = line_re.search(line)
        if not match:
            continue
        entries.append(
            {
                "index": int(match.group(1)),
                "kind": match.group(2),
                "identity": match.group(3).strip(),
                "base": int(match.group(4), 16),
                "end": int(match.group(5), 16),
            }
        )
    return entries


def _extract_records(data, translator):
    """Extract and de-duplicate loaded-image records from a mapped dump."""
    debug_info = {
        "signature_hits": 0,
        "candidate_rejections": {
            "too_short": 0,
            "bad_revision": 0,
            "null_system_table_pointer": 0,
            "zero_base_or_size": 0,
            "oversized_image": 0,
            "wrapped_image_range": 0,
        },
        "candidate_count": 0,
        "system_table_signature_unreadable": 0,
        "signature_valid_candidate_count": 0,
        "dominant_system_table": None,
        "require_signature_valid": False,
        "filtered_out_other_system_table": 0,
        "filtered_out_invalid_signature": 0,
        "filtered_count": 0,
        "dedup_replaced_records": 0,
        "dedup_unique_count": 0,
    }
    candidates = []
    for sig_offset in mu.iter_loaded_image_signature_offsets(data):
        debug_info["signature_hits"] += 1
        parsed, rejection_reason = _classify_loaded_image_candidate(data, sig_offset)
        if parsed is None:
            debug_info["candidate_rejections"][rejection_reason] += 1
            continue

        system_table_signature_value = mu.read_runtime_u64(data, translator, parsed.system_table_pointer)
        system_table_signature_valid = (
            system_table_signature_value == cs.EFI_SYSTEM_TABLE_SIGNATURE
            if system_table_signature_value is not None
            else False
        )
        if system_table_signature_value is None:
            debug_info["system_table_signature_unreadable"] += 1

        identity = _extract_identity_from_device_path(data, translator, parsed.file_path_pointer)
        candidates.append(
            ImageRecord(
                struct_offset=parsed.struct_offset,
                revision=parsed.revision,
                system_table_pointer=parsed.system_table_pointer,
                system_table_signature_valid=system_table_signature_valid,
                image_base=parsed.image_base,
                image_size=parsed.image_size,
                image_end=parsed.image_end,
                file_path_pointer=parsed.file_path_pointer,
                identity=identity,
            )
        )

    if not candidates:
        return [], debug_info

    debug_info["candidate_count"] = len(candidates)

    signature_valid_system_tables = [
        rec.system_table_pointer for rec in candidates if rec.system_table_signature_valid
    ]
    debug_info["signature_valid_candidate_count"] = len(signature_valid_system_tables)
    system_table_pool = signature_valid_system_tables or [rec.system_table_pointer for rec in candidates]
    dominant_system_table = max(set(system_table_pool), key=system_table_pool.count)
    require_signature_valid = bool(signature_valid_system_tables)
    debug_info["dominant_system_table"] = dominant_system_table
    debug_info["require_signature_valid"] = require_signature_valid

    filtered = []
    for rec in candidates:
        if rec.system_table_pointer != dominant_system_table:
            debug_info["filtered_out_other_system_table"] += 1
            continue
        if require_signature_valid and not rec.system_table_signature_valid:
            debug_info["filtered_out_invalid_signature"] += 1
            continue
        filtered.append(rec)
    debug_info["filtered_count"] = len(filtered)

    def _record_score(record):
        """Prefer records with validated system tables and richer identities."""
        score = 0
        if record.system_table_signature_valid:
            score += 2
        if record.identity != "unknown":
            score += 1
        return score

    # De-duplicate by [base, end] to drop duplicate structure instances.
    dedup = {}
    for record in filtered:
        key = (record.image_base, record.image_end)
        current = dedup.get(key)
        if current is None or _record_score(record) > _record_score(current):
            if current is not None:
                debug_info["dedup_replaced_records"] += 1
            dedup[key] = record
    debug_info["dedup_unique_count"] = len(dedup)
    return list(dedup.values()), debug_info


def _write_metadata(output_dir, records):
    """Write carving metadata to CSV and JSON files."""
    os.makedirs(output_dir, exist_ok=True)
    csv_path = os.path.join(output_dir, "images.csv")
    json_path = os.path.join(output_dir, "images.json")

    records_sorted = sorted(records, key=lambda r: r.image_base)

    with open(csv_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "struct_offset",
                "revision",
                "system_table_pointer",
                "system_table_signature_valid",
                "image_base",
                "image_end",
                "image_size",
                "file_path_pointer",
                "identity",
            ]
        )
        for rec in records_sorted:
            writer.writerow(
                [
                    f"0x{rec.struct_offset:016X}",
                    f"0x{rec.revision:08X}",
                    f"0x{rec.system_table_pointer:016X}",
                    str(rec.system_table_signature_valid),
                    f"0x{rec.image_base:016X}",
                    f"0x{rec.image_end:016X}",
                    f"0x{rec.image_size:016X}",
                    f"0x{rec.file_path_pointer:016X}",
                    rec.identity,
                ]
            )

    payload = [
        {
            "struct_offset": rec.struct_offset,
            "revision": rec.revision,
            "system_table_pointer": rec.system_table_pointer,
            "system_table_signature_valid": rec.system_table_signature_valid,
            "image_base": rec.image_base,
            "image_end": rec.image_end,
            "image_size": rec.image_size,
            "file_path_pointer": rec.file_path_pointer,
            "identity": rec.identity,
        }
        for rec in records_sorted
    ]
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)

    return csv_path, json_path


def _write_images_if_requested(output_dir, data, translator, records):
    """Write carved image bytes for records that translate cleanly into the dump."""
    image_dir = os.path.join(output_dir, "images")
    os.makedirs(image_dir, exist_ok=True)

    extracted = 0
    skipped = 0
    debug_info = {
        "skipped_untranslated": 0,
        "skipped_out_of_bounds": 0,
        "skip_preview": [],
    }

    for rec in records:
        start_off = translator.to_file_offset(rec.image_base)
        if start_off is None:
            skipped += 1
            debug_info["skipped_untranslated"] += 1
            if len(debug_info["skip_preview"]) < 5:
                debug_info["skip_preview"].append(
                    {
                        "image_base": rec.image_base,
                        "identity": rec.identity,
                        "reason": "runtime address could not be translated",
                    }
                )
            continue

        end_off = start_off + rec.image_size
        if end_off > len(data):
            skipped += 1
            debug_info["skipped_out_of_bounds"] += 1
            if len(debug_info["skip_preview"]) < 5:
                debug_info["skip_preview"].append(
                    {
                        "image_base": rec.image_base,
                        "identity": rec.identity,
                        "reason": "translated range extends beyond the dump size",
                    }
                )
            continue

        identity_tag = _sanitize_filename(rec.identity)
        output_name = f"image_{rec.image_base:016X}_{identity_tag}.bin"
        output_path = os.path.join(image_dir, output_name)
        with open(output_path, "wb") as handle:
            handle.write(data[start_off:end_off])
        extracted += 1

    return extracted, skipped, image_dir, debug_info


def _parse_pe_header_at(data, offset):
    """Parse enough of a PE header to match it against loaded-image metadata."""
    if offset + cs.PE_MIN_HEADER_SIZE > len(data):
        return None
    if data[offset:offset + 2] != cs.PE_DOS_SIGNATURE:
        return None

    e_lfanew = struct.unpack_from("<I", data, offset + 0x3C)[0]
    nt_offset = offset + e_lfanew
    optional_offset = nt_offset + 0x18
    if optional_offset + 0x60 > len(data):
        return None
    if data[nt_offset:nt_offset + 4] != cs.PE_NT_SIGNATURE:
        return None

    optional_magic = struct.unpack_from("<H", data, optional_offset)[0]
    if optional_magic == cs.PE32_PLUS_MAGIC:
        image_base = struct.unpack_from("<Q", data, optional_offset + 24)[0]
    elif optional_magic == cs.PE32_MAGIC:
        image_base = struct.unpack_from("<I", data, optional_offset + 28)[0]
    else:
        return None

    size_of_image = struct.unpack_from("<I", data, optional_offset + 56)[0]
    if image_base == 0 or size_of_image == 0 or size_of_image > cs.MAX_IMAGE_SIZE:
        return None

    return PeHeaderCandidate(
        offset=offset,
        image_base=image_base,
        size_of_image=size_of_image,
    )


def _pe_size_matches_record(pe_size, record_size):
    """Return whether a PE SizeOfImage is consistent with the loaded-image size."""
    if pe_size == record_size:
        return True
    if pe_size < record_size and (record_size - pe_size) <= cs.PE_SIZE_TOLERANCE:
        return True
    return False


def _select_unique_pe_candidate(candidates, record):
    """Select a unique PE-header candidate for one loaded-image record."""
    size_matches = [
        candidate
        for candidate in candidates
        if _pe_size_matches_record(candidate.size_of_image, record.image_size)
    ]
    exact_matches = [
        candidate
        for candidate in size_matches
        if candidate.size_of_image == record.image_size
    ]

    if len(exact_matches) == 1:
        return exact_matches[0]
    if len(exact_matches) > 1:
        return None
    if len(size_matches) == 1:
        return size_matches[0]
    return None


def _write_images_by_pe_header_scan(output_dir, data, records):
    """Extract images by scanning for PE headers that match loaded-image metadata."""
    image_dir = os.path.join(output_dir, "images")
    os.makedirs(image_dir, exist_ok=True)

    records_by_base = {record.image_base: record for record in records}
    candidates_by_base = {record.image_base: [] for record in records}
    debug_info = {
        "pe_signature_hits": 0,
        "pe_candidates_for_records": 0,
        "skipped_no_pe_match": 0,
        "skipped_ambiguous_pe_match": 0,
        "skipped_out_of_bounds": 0,
        "skip_preview": [],
    }

    offset = 0
    while True:
        offset = data.find(cs.PE_DOS_SIGNATURE, offset)
        if offset == -1:
            break

        debug_info["pe_signature_hits"] += 1
        candidate = _parse_pe_header_at(data, offset)
        if candidate is not None and candidate.image_base in records_by_base:
            candidates_by_base[candidate.image_base].append(candidate)
            debug_info["pe_candidates_for_records"] += 1
        offset += 1

    extracted = 0
    skipped = 0
    for record in records:
        candidates = candidates_by_base.get(record.image_base, [])
        selected = _select_unique_pe_candidate(candidates, record)
        if selected is None:
            skipped += 1
            if not candidates:
                debug_info["skipped_no_pe_match"] += 1
                reason = "no PE header matched image base"
            else:
                debug_info["skipped_ambiguous_pe_match"] += 1
                reason = "multiple or size-inconsistent PE headers matched image base"
            if len(debug_info["skip_preview"]) < 5:
                debug_info["skip_preview"].append(
                    {
                        "image_base": record.image_base,
                        "identity": record.identity,
                        "reason": reason,
                    }
                )
            continue

        end_off = selected.offset + record.image_size
        if end_off > len(data):
            skipped += 1
            debug_info["skipped_out_of_bounds"] += 1
            if len(debug_info["skip_preview"]) < 5:
                debug_info["skip_preview"].append(
                    {
                        "image_base": record.image_base,
                        "identity": record.identity,
                        "reason": "PE header match extends beyond the dump size",
                    }
                )
            continue

        identity_tag = _sanitize_filename(record.identity)
        output_name = f"image_{record.image_base:016X}_{identity_tag}.bin"
        output_path = os.path.join(image_dir, output_name)
        with open(output_path, "wb") as handle:
            handle.write(data[selected.offset:end_off])
        extracted += 1

    return extracted, skipped, image_dir, debug_info


def _print_debug_report(debug_info):
    """Print detailed carving diagnostics collected during one run."""
    print("[debug] UEFIImageCarving diagnostics")
    print(f"[debug] Translation mode: {debug_info['translation_mode']}")
    print(f"[debug] Signature hits: {debug_info['signature_hits']}")

    rejection_counts = debug_info["candidate_rejections"]
    print("[debug] Candidate rejection counts:")
    for reason, count in rejection_counts.items():
        print(f"[debug]   {reason}: {count}")

    print(
        "[debug] Candidate summary: "
        f"accepted={debug_info['candidate_count']} "
        f"system_table_signature_unreadable={debug_info['system_table_signature_unreadable']} "
        f"signature_valid={debug_info['signature_valid_candidate_count']}"
    )

    dominant_system_table = debug_info["dominant_system_table"]
    if dominant_system_table is None:
        print("[debug] No valid loaded-image candidates survived structure validation.")
    else:
        print(
            "[debug] Filtering summary: "
            f"dominant_system_table=0x{dominant_system_table:016X} "
            f"require_signature_valid={debug_info['require_signature_valid']} "
            f"filtered_out_other_system_table={debug_info['filtered_out_other_system_table']} "
            f"filtered_out_invalid_signature={debug_info['filtered_out_invalid_signature']} "
            f"retained={debug_info['filtered_count']}"
        )

    print(
        "[debug] Deduplication summary: "
        f"replaced_records={debug_info['dedup_replaced_records']} "
        f"unique_records={debug_info['dedup_unique_count']}"
    )

    extraction_debug = debug_info.get("extraction")
    if extraction_debug is None:
        return

    if "pe_signature_hits" in extraction_debug:
        print(
            "[debug] PE-header extraction summary: "
            f"pe_signature_hits={extraction_debug['pe_signature_hits']} "
            f"pe_candidates_for_records={extraction_debug['pe_candidates_for_records']} "
            f"skipped_no_pe_match={extraction_debug['skipped_no_pe_match']} "
            f"skipped_ambiguous_pe_match={extraction_debug['skipped_ambiguous_pe_match']} "
            f"skipped_out_of_bounds={extraction_debug['skipped_out_of_bounds']}"
        )
    else:
        print(
            "[debug] Binary extraction summary: "
            f"skipped_untranslated={extraction_debug['skipped_untranslated']} "
            f"skipped_out_of_bounds={extraction_debug['skipped_out_of_bounds']}"
        )
    for preview in extraction_debug["skip_preview"]:
        print(
            "[debug]   skip "
            f"base=0x{preview['image_base']:016X} "
            f"identity={preview['identity']} "
            f"reason={preview['reason']}"
        )


def _print_verify_report(records, reference_entries):
    """Print a small verification summary against a reference image list."""
    found = {(r.image_base, r.image_end) for r in records}
    reference = {(e["base"], e["end"]) for e in reference_entries}

    matched = len(found & reference)
    only_found = found - reference
    only_reference = reference - found

    print(f"Verification: matched={matched} reference={len(reference)} found={len(found)}")
    print(f"Verification: extra_in_dump={len(only_found)} missing_from_dump={len(only_reference)}")

    if only_found:
        preview = sorted(only_found)[:5]
        for base, end in preview:
            print(f"  EXTRA  Base=0x{base:016X} End=0x{end:016X}")

    if only_reference:
        preview = sorted(only_reference)[:5]
        for base, end in preview:
            print(f"  MISSING Base=0x{base:016X} End=0x{end:016X}")


def carve_images(
    dump_path: str,
    output_dir: str,
    memory_map_path: Optional[str] = None,
    verify_path: Optional[str] = None,
    extract_binaries: bool = False,
    assume_identity_map: bool = False,
    pe_header_fallback: bool = False,
) -> dict[str, Any]:
    """Carve loaded images from a dump and emit their associated metadata."""
    dump_data = mu.open_memory_dump(dump_path)
    try:
        regions = None
        if memory_map_path:
            regions = mu.load_memory_map_regions(memory_map_path)

        translator = mu.AddressTranslator(dump_size=len(dump_data), regions=regions)
        records, debug_info = _extract_records(dump_data, translator)
        debug_info["translation_mode"] = "memory-map" if regions is not None else "identity-fallback"
        csv_path, json_path = _write_metadata(output_dir, records)

        result = {
            "records": records,
            "csv_path": csv_path,
            "json_path": json_path,
            "regions": regions,
            "image_dir": None,
            "extracted": 0,
            "skipped": 0,
            "reference_entries": None,
            "debug_info": debug_info,
        }

        if extract_binaries and pe_header_fallback and regions is None:
            extracted, skipped, image_dir, extraction_debug = _write_images_by_pe_header_scan(
                output_dir,
                dump_data,
                records,
            )
            result.update(
                {
                    "image_dir": image_dir,
                    "extracted": extracted,
                    "skipped": skipped,
                }
            )
            debug_info["extraction"] = extraction_debug
        elif extract_binaries and (regions is not None or assume_identity_map):
            extracted, skipped, image_dir, extraction_debug = _write_images_if_requested(
                output_dir,
                dump_data,
                translator,
                records,
            )
            result.update(
                {
                    "image_dir": image_dir,
                    "extracted": extracted,
                    "skipped": skipped,
                }
            )
            debug_info["extraction"] = extraction_debug

        if verify_path:
            reference_entries = _load_reference_image_list(verify_path)
            result["reference_entries"] = reference_entries

        return result
    finally:
        dump_data.close()


def run(args) -> None:
    """Execute image carving from the CLI entrypoint."""
    if (
        bool(getattr(args, "extract_binaries", False))
        and not getattr(args, "memory_map", None)
        and not bool(getattr(args, "assume_identity_map", False))
        and not bool(getattr(args, "pe_header_fallback", False))
    ):
        raise SystemExit(
            "error: -memory_map is required when -extract_binaries is used. "
            "Run without -extract_binaries for metadata-only output, or use "
            "-pe_header_fallback or -assume_identity_map when Memory_Map.txt is unavailable."
        )

    result = carve_images(
        dump_path=args.f,
        output_dir=args.o,
        memory_map_path=getattr(args, "memory_map", None),
        verify_path=getattr(args, "verify", None),
        extract_binaries=bool(getattr(args, "extract_binaries", False)),
        assume_identity_map=bool(getattr(args, "assume_identity_map", False)),
        pe_header_fallback=bool(getattr(args, "pe_header_fallback", False)),
    )

    regions = result["regions"]
    if regions is not None:
        print(f"Loaded {len(regions)} memory-map regions from {args.memory_map}")

    records = result["records"]
    csv_path = result["csv_path"]
    json_path = result["json_path"]
    image_dir = result["image_dir"]
    extracted = result["extracted"]
    skipped = result["skipped"]
    reference_entries = result["reference_entries"]
    debug_info = result["debug_info"]

    print(f"Detected {len(records)} unique loaded image records")
    print(f"Metadata CSV: {csv_path}")
    print(f"Metadata JSON: {json_path}")

    if getattr(args, "extract_binaries", False):
        print(f"Binary extraction: extracted={extracted} skipped={skipped} output={image_dir}")

    if reference_entries is not None:
        print(f"Loaded {len(reference_entries)} reference entries from {args.verify}")
        _print_verify_report(records, reference_entries)

    if bool(getattr(args, "debug", False)):
        _print_debug_report(debug_info)


plugin_info = {
    "name": "UEFI Image Carving",
    "description": (
        "Carve loaded UEFI images from a memory dump, emit metadata, and optionally "
        "compare the results against a dumper-produced ImageList reference."
    ),
    "arguments": [
        {"name": "-f", "help": "Memory dump file path", "required": True},
        {"name": "-o", "help": "Output directory for metadata/results", "required": True},
        {
            "name": "-memory_map",
            "help": (
                "Path to Memory_Map.txt produced by the dumper. Required for normal "
                "binary extraction; optional for metadata-only output or explicit "
                "fallback extraction modes."
            ),
            "required": False,
        },
        {
            "name": "-verify",
            "help": (
                "Optional ImageList*.txt produced by the dumper. Used only to compare "
                "detected images against the recorded base/end and GUID/path list."
            ),
            "required": False,
        },
        {
            "name": "-extract_binaries",
            "help": (
                "Write carved image binaries under <output>/images. Requires -memory_map "
                "for reliable runtime-to-file translation unless -pe_header_fallback "
                "or -assume_identity_map is used."
            ),
            "action": "store_true",
        },
        {
            "name": "-pe_header_fallback",
            "help": (
                "Allow binary extraction without -memory_map by scanning the dump for "
                "unique PE headers whose ImageBase matches loaded-image metadata."
            ),
            "action": "store_true",
        },
        {
            "name": "-assume_identity_map",
            "help": (
                "Allow binary extraction without -memory_map by assuming runtime addresses "
                "match dump file offsets. Use only for dumps known to be identity-mapped."
            ),
            "action": "store_true",
        },
        {
            "name": "-debug",
            "help": "Print detailed carving diagnostics, including filtering and extraction skip counts.",
            "action": "store_true",
        },
    ],
}
