import mmap
import os
import re
import struct
from collections import Counter
from bisect import bisect_right
from dataclasses import dataclass
from typing import Optional

from uefi_dump_analysis.utilities import constants as cs

MEDIA_DEVICE_PATH = 0x04
MEDIA_FW_VOL_FILEPATH_DP = 0x06
MEDIA_FILEPATH_DP = 0x04
END_DEVICE_PATH_TYPE = 0x7F

MAX_IMAGE_SIZE = 0x40000000  # 1 GiB safety bound to reduce false-positive "ldri" hits.


@dataclass(frozen=True)
class AddressRegion:
    start: int
    end: int
    file_offset_start: int


class AddressTranslator:
    """
    Runtime-address to dump-file-offset translator.

    If no regions are provided, fallback mode assumes identity mapping
    (address == file offset), which only works for some dump layouts.
    """

    def __init__(self, dump_size, regions=None):
        self.dump_size = dump_size
        self.regions = regions or []
        self._region_starts = [r.start for r in self.regions]

    def _region_index_for_address(self, address):
        if not self.regions:
            return None
        index = bisect_right(self._region_starts, address) - 1
        if index < 0:
            return None
        region = self.regions[index]
        if address > region.end:
            return None
        return index

    def region_for_address(self, address):
        index = self._region_index_for_address(address)
        if index is None:
            return None
        return self.regions[index]

    def to_file_offset(self, address):
        if address < 0:
            return None

        if not self.regions:
            if address < self.dump_size:
                return address
            return None

        region = self.region_for_address(address)
        if region is None:
            return None

        offset = region.file_offset_start + (address - region.start)
        if 0 <= offset < self.dump_size:
            return offset
        return None

    def read_runtime(self, dump_data, runtime_address, size, pad=False):
        if size < 0:
            return None
        if size == 0:
            return b""

        if not self.regions:
            start = self.to_file_offset(runtime_address)
            if start is None:
                return b"\x00" * size if pad else None
            end = start + size
            if end <= len(dump_data):
                return dump_data[start:end]
            if not pad:
                return None
            available = max(0, len(dump_data) - start)
            return dump_data[start:start + available] + (b"\x00" * (size - available))

        chunks = []
        current = runtime_address
        remaining = size
        while remaining > 0:
            region = self.region_for_address(current)
            if region is None:
                if not pad:
                    return None
                chunks.append(b"\x00" * remaining)
                break

            region_remaining = (region.end - current) + 1
            take = min(remaining, region_remaining)
            start = self.to_file_offset(current)
            if start is None:
                if not pad:
                    return None
                chunks.append(b"\x00" * remaining)
                break

            end = start + take
            if end > len(dump_data):
                if not pad:
                    return None
                available = max(0, len(dump_data) - start)
                chunks.append(dump_data[start:start + available])
                chunks.append(b"\x00" * (take - available))
            else:
                chunks.append(dump_data[start:end])

            current += take
            remaining -= take

        return b"".join(chunks)


def _is_offset_in_bounds(data, offset, size=1):
    return 0 <= offset <= len(data) - size


def _decode_text_file(path):
    with open(path, "rb") as handle:
        raw = handle.read()
    for encoding in ("utf-16", "utf-16-le", "utf-8"):
        try:
            return raw.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    return raw.decode("latin1"), "latin1"


def load_memory_map_regions(memory_map_path):
    if not memory_map_path:
        return []
    if not os.path.exists(memory_map_path):
        raise FileNotFoundError(f"Memory map file not found: {memory_map_path}")

    text, _ = _decode_text_file(memory_map_path)
    line_re = re.compile(
        r"Start=0x([0-9A-Fa-f]+)\s+End=0x([0-9A-Fa-f]+)\s+#Pages=0x([0-9A-Fa-f]+)"
    )

    raw_ranges = []
    for line in text.splitlines():
        match = line_re.search(line)
        if not match:
            continue
        start = int(match.group(1), 16)
        end = int(match.group(2), 16)
        if end < start:
            continue
        raw_ranges.append((start, end))

    raw_ranges.sort(key=lambda item: item[0])
    file_offset = 0
    regions = []
    for start, end in raw_ranges:
        regions.append(AddressRegion(start=start, end=end, file_offset_start=file_offset))
        file_offset += (end - start + 1)
    return regions


def build_address_translator(dump_data, memory_map_path: Optional[str] = None):
    regions = load_memory_map_regions(memory_map_path) if memory_map_path else []
    return AddressTranslator(dump_size=len(dump_data), regions=regions)


def open_memory_dump(file_path: str):
    with open(file_path, "rb") as handle:
        return mmap.mmap(handle.fileno(), length=0, access=mmap.ACCESS_READ)


def read_runtime_bytes(dump_data, translator, runtime_address, size, pad=False):
    if translator is None:
        translator = AddressTranslator(len(dump_data))
    return translator.read_runtime(dump_data, runtime_address, size, pad=pad)


def _read_runtime_u64(dump_data, translator, runtime_address):
    data = read_runtime_bytes(dump_data, translator, runtime_address, 8, pad=False)
    if data is None or len(data) < 8:
        return None
    return struct.unpack("<Q", data)[0]


def extract_image_base_and_size(data, offset):
    image_base_page = struct.unpack_from("<Q", data, offset + cs.IMAGE_BASE_OFFSET)[0]
    image_size = struct.unpack_from("<Q", data, offset + cs.IMAGE_SIZE_OFFSET)[0]
    return image_base_page, image_size


def _try_decode_utf16_path(raw_bytes):
    if not raw_bytes:
        return None

    if len(raw_bytes) % 2:
        raw_bytes = raw_bytes[:-1]
    if not raw_bytes:
        return None

    text = raw_bytes.decode("utf-16-le", errors="ignore").split("\x00", 1)[0].strip()
    if not text:
        return None

    lowered = text.lower()
    has_known_suffix = any(ext in lowered for ext in [".efi", ".dll", ".bin", ".exe"])
    if ("\\" in text or "/" in text) and has_known_suffix:
        return text
    return None


def _try_parse_guid(raw_bytes):
    if len(raw_bytes) < cs.GUID_SIZE:
        return None

    guid = struct.unpack_from("<I2H8B", raw_bytes[:cs.GUID_SIZE])
    return (
        f"{guid[0]:08X}-{guid[1]:04X}-{guid[2]:04X}-"
        f"{guid[3]:02X}{guid[4]:02X}-"
        f"{''.join(f'{byte:02X}' for byte in guid[5:])}"
    )


def _parse_device_path_node(data, offset):
    if not _is_offset_in_bounds(data, offset, 4):
        return None

    node_type, node_subtype, node_length = struct.unpack_from("<BBH", data, offset)
    if node_length < 4 or not _is_offset_in_bounds(data, offset, node_length):
        return None
    return node_type, node_subtype, node_length


def _extract_identity_from_device_path(dump_data, translator, pointer_address, max_bytes=512):
    if translator is None:
        translator = AddressTranslator(len(dump_data))

    current_offset = translator.to_file_offset(pointer_address)
    if current_offset is None or not _is_offset_in_bounds(dump_data, current_offset, 4):
        return "unknown"

    bytes_remaining = max_bytes
    while bytes_remaining >= 4:
        node = _parse_device_path_node(dump_data, current_offset)
        if node is None:
            return "unknown"

        node_type, node_subtype, node_length = node
        payload_offset = current_offset + 4
        payload_length = node_length - 4
        payload = dump_data[payload_offset:payload_offset + payload_length]

        if node_type == MEDIA_DEVICE_PATH:
            if node_subtype == MEDIA_FW_VOL_FILEPATH_DP:
                guid = _try_parse_guid(payload)
                if guid and guid != "00000000-0000-0000-0000-000000000000":
                    return guid
            elif node_subtype == MEDIA_FILEPATH_DP:
                path = _try_decode_utf16_path(payload)
                if path:
                    return path

        if node_type == END_DEVICE_PATH_TYPE:
            break

        current_offset += node_length
        bytes_remaining -= node_length

    return "unknown"


def extract_guid_or_path(data, start_offset, max_bytes=512):
    if not _is_offset_in_bounds(data, start_offset, 8):
        raise ValueError("Start offset for pointer is out of bounds")

    pointer_value = struct.unpack_from("<Q", data, start_offset)[0]
    translator = AddressTranslator(len(data))
    return _extract_identity_from_device_path(data, translator, pointer_value, max_bytes=max_bytes)


def _iter_signature_offsets(dump_data):
    index = 0
    while True:
        index = dump_data.find(cs.SIGNATURE, index)
        if index == -1:
            break
        yield index
        index += 1


def extract_images(
    dump_data,
    memory_map_path: Optional[str] = None,
    quiet: bool = True,
    return_details: bool = False,
    max_image_size: int = MAX_IMAGE_SIZE,
):
    translator = build_address_translator(dump_data, memory_map_path)
    candidates = []

    for index in _iter_signature_offsets(dump_data):
        if len(dump_data) - index < cs.IMAGE_SIZE_OFFSET + 8:
            continue

        try:
            revision = struct.unpack_from("<I", dump_data, index + cs.IMAGE_REVISION_OFFSET)[0]
        except struct.error:
            continue
        if revision != cs.EFI_LOADED_IMAGE_PROTOCOL_REVISION:
            continue

        try:
            system_table_pointer = struct.unpack_from("<Q", dump_data, index + cs.SYSTEM_TABLE_OFFSET)[0]
        except struct.error:
            continue
        if system_table_pointer == 0:
            continue

        image_base, image_size = extract_image_base_and_size(dump_data, index)
        if image_base == 0 or image_size == 0:
            continue
        if image_size > max_image_size:
            continue

        image_end = image_base + image_size
        if image_end <= image_base:
            continue

        try:
            file_path_pointer = struct.unpack_from("<Q", dump_data, index + cs.GUID_OFFSET)[0]
        except struct.error:
            continue

        identity = _extract_identity_from_device_path(dump_data, translator, file_path_pointer)
        system_table_signature_value = _read_runtime_u64(dump_data, translator, system_table_pointer)
        system_table_signature_valid = (
            system_table_signature_value == cs.EFI_SYSTEM_TABLE_SIGNATURE
            if system_table_signature_value is not None
            else False
        )

        candidates.append(
            {
                "struct_offset": index,
                "revision": revision,
                "system_table_pointer": system_table_pointer,
                "system_table_signature_valid": system_table_signature_valid,
                "image_base": image_base,
                "image_end": image_end,
                "image_size": image_size,
                "file_path_pointer": file_path_pointer,
                "identity": identity,
            }
        )

    if not candidates:
        return [] if return_details else []

    signature_valid_system_tables = [
        item["system_table_pointer"] for item in candidates if item["system_table_signature_valid"]
    ]
    system_table_pool = signature_valid_system_tables or [
        item["system_table_pointer"] for item in candidates
    ]
    dominant_system_table = Counter(system_table_pool).most_common(1)[0][0]
    require_signature_valid = bool(signature_valid_system_tables)

    filtered = []
    for item in candidates:
        if item["system_table_pointer"] != dominant_system_table:
            continue
        if require_signature_valid and not item["system_table_signature_valid"]:
            continue
        filtered.append(item)

    def _record_score(record):
        score = 0
        if record.get("system_table_signature_valid"):
            score += 2
        if record.get("identity") and record["identity"] != "unknown":
            score += 1
        return score

    # De-duplicate same image range if multiple structures point at it.
    dedup = {}
    for rec in filtered:
        key = (rec["image_base"], rec["image_end"])
        current = dedup.get(key)
        if current is None or _record_score(rec) > _record_score(current):
            dedup[key] = rec

    deduped = list(dedup.values())
    deduped.sort(key=lambda item: item["image_base"])

    if not quiet:
        for idx, rec in enumerate(deduped, start=1):
            print(f"Structure {idx}:")
            print(f"  Revision: 0x{rec['revision']:08X}")
            print(f"  SystemTable: 0x{rec['system_table_pointer']:016X}")
            print(f"  SystemTableSignatureValid: {rec['system_table_signature_valid']}")
            print(f"  ImageBasePage: 0x{rec['image_base']:016X}")
            print(f"  ImageSize: 0x{rec['image_size']:016X}")
            print(f"  ImageEndAddress: 0x{rec['image_end']:016X}")
            print(f"  GUID/Path: {rec['identity']}")

    if return_details:
        return deduped

    return [(rec["image_base"], rec["image_end"], rec["identity"]) for rec in deduped]
