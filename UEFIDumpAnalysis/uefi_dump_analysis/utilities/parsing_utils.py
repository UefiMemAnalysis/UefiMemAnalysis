import struct
from typing import Sequence

from uefi_dump_analysis.utilities import constants as cs

EFI_TABLE_HEADER_FORMAT = "<QIIII"
EFI_TABLE_HEADER_SIZE = struct.calcsize(EFI_TABLE_HEADER_FORMAT)


def parse_function_pointers(table_data: bytes, function_names: Sequence[str]) -> dict[str, int]:
    """Parses function pointers from a service table payload safely."""
    pointers = {}
    current_offset = cs.TABLES_HEADER_SIZE

    for function_name in function_names:
        if current_offset + 8 > len(table_data):
            break
        pointers[function_name] = struct.unpack_from("<Q", table_data, current_offset)[0]
        current_offset += 8

    return pointers


def find_services_tables(dump_data, signature: bytes, table_size: int):
    """
    Find candidate EFI service tables by signature.

    The scan is defensive: it validates table bounds and header size before
    yielding results so malformed dumps do not crash parsing.
    """
    if not signature or table_size < cs.TABLES_HEADER_SIZE:
        return []

    tables = []
    offset = 0
    dump_size = len(dump_data)

    while True:
        signature_offset = dump_data.find(signature, offset)
        if signature_offset == -1:
            break

        # Always advance to avoid rescanning the same byte on rejected candidates.
        offset = signature_offset + 1

        table_start = signature_offset
        table_end = table_start + table_size
        if table_end > dump_size:
            continue

        table_data = dump_data[table_start:table_end]
        if len(table_data) < EFI_TABLE_HEADER_SIZE:
            continue

        try:
            header = struct.unpack_from(EFI_TABLE_HEADER_FORMAT, table_data, 0)
        except struct.error:
            continue

        signature_qword, revision, header_size, crc32, reserved = header

        # Reject inconsistent headers (common for signature false positives).
        if header_size < EFI_TABLE_HEADER_SIZE or header_size > table_size:
            continue

        major_revision = revision >> 16
        minor_revision = revision & 0xFFFF
        signature_ascii = signature_qword.to_bytes(8, "little").decode("ascii", errors="replace")

        table_info = {
            "Pointer": signature_offset,
            "SignatureHex": f"{signature_qword:016X}",
            "SignatureASCII": signature_ascii,
            "RevisionHex": f"{revision:08X}",
            "Revision": f"{major_revision}.{minor_revision}",
            "HeaderSize": header_size,
            "CRC32": crc32,
            "Reserved": reserved,
        }

        tables.append((table_data, table_info))

    return tables
