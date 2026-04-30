"""Flag path-backed loaded images that are not explicitly whitelisted."""

import json
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Set, TypedDict

from uefi_dump_analysis.utilities import memory_utils as mu

ARTIFACTS_DIR = Path("artifacts")
DEFAULT_REPORT_PATH = ARTIFACTS_DIR / "reports" / "image_load_path_report.txt"
DEFAULT_BOOT_WHITELIST = {
    r"\efi\boot\bootx64.efi",
    r"\efi\boot\bootia32.efi",
    r"\efi\boot\bootaa64.efi",
    r"\efi\boot\bootarm.efi",
    r"\efi\boot\bootriscv64.efi",
}


class LoadedImageRecord(TypedDict):
    """Minimal loaded-image metadata consumed by this plugin."""

    image_base: int
    image_end: int
    identity: str


class ClassifiedImagePath(TypedDict):
    """Classification result for one path-backed loaded image."""

    image_base: int
    image_end: int
    identity: str
    normalized_identity: str
    status: str
    reason: str


def _normalize_path_identity(identity: str) -> str:
    """Normalize a UEFI path identity for exact whitelist comparison."""
    normalized = str(identity).strip().replace("/", "\\").strip('"').strip("'")
    while "\\\\" in normalized:
        normalized = normalized.replace("\\\\", "\\")
    return normalized.lower()


def _is_path_identity(identity: object) -> bool:
    """Return ``True`` when an identity string looks like a filesystem path."""
    if not isinstance(identity, str):
        return False
    return ("\\" in identity or "/" in identity) and identity.strip() != ""


def _split_path_values(values: Optional[Sequence[str]]) -> List[str]:
    """Split repeated CLI whitelist arguments into individual path strings."""
    if not values:
        return []

    parsed: List[str] = []
    for raw in values:
        if not raw:
            continue
        for token in raw.split(","):
            value = token.strip()
            if value:
                parsed.append(value)
    return parsed


def _load_whitelist_file(path_value: Optional[str]) -> List[str]:
    """Read newline-delimited whitelist paths from disk."""
    if not path_value:
        return []

    whitelist_path = Path(path_value)
    if not whitelist_path.exists():
        raise FileNotFoundError(f"Whitelist file not found: {whitelist_path}")

    return [
        line.strip()
        for line in whitelist_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _build_effective_whitelist(
    inline_values: Optional[Sequence[str]],
    whitelist_file: Optional[str],
) -> Set[str]:
    """Build the exact path whitelist used for classification."""
    entries = set(DEFAULT_BOOT_WHITELIST)
    for path_value in _split_path_values(inline_values):
        entries.add(_normalize_path_identity(path_value))
    for path_value in _load_whitelist_file(whitelist_file):
        entries.add(_normalize_path_identity(path_value))
    return entries


def _resolve_metadata_json(path_value: str) -> Path:
    """Resolve a carving-output directory or ``images.json`` path to the JSON file."""
    path = Path(path_value)
    if not path.exists():
        raise FileNotFoundError(f"Carving metadata path not found: {path}")

    if path.is_dir():
        json_path = path / "images.json"
        if not json_path.exists():
            raise FileNotFoundError(f"Expected images.json under carving directory: {path}")
        return json_path

    return path


def _coerce_loaded_image_records(raw_records: Iterable[dict]) -> List[LoadedImageRecord]:
    """Convert generic metadata dictionaries into the record shape used here."""
    records: List[LoadedImageRecord] = []
    for record in raw_records:
        try:
            image_base = int(record["image_base"])
            image_end = int(record["image_end"])
            identity = str(record.get("identity", "unknown"))
        except (KeyError, TypeError, ValueError):
            continue
        records.append(
            {
                "image_base": image_base,
                "image_end": image_end,
                "identity": identity,
            }
        )
    return sorted(records, key=lambda item: item["image_base"])


def _load_records_from_metadata(path_value: str) -> List[LoadedImageRecord]:
    """Load carving metadata records from an ``images.json`` file."""
    json_path = _resolve_metadata_json(path_value)
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError(f"Unexpected metadata format in {json_path}")
    return _coerce_loaded_image_records(payload)


def _load_records_from_dump(dump_file: str, memory_map_path: Optional[str]) -> List[LoadedImageRecord]:
    """Extract loaded-image records directly from a dump."""
    dump_data = mu.open_memory_dump(dump_file)
    try:
        records = mu.extract_images(
            dump_data,
            memory_map_path=memory_map_path,
            quiet=True,
            return_details=True,
        )
    finally:
        dump_data.close()
    return _coerce_loaded_image_records(records)


def _load_records(args) -> tuple[List[LoadedImageRecord], str]:
    """Load image records from either a dump or an existing carving result."""
    carve_dir = getattr(args, "carve_dir", None)
    if carve_dir:
        return _load_records_from_metadata(carve_dir), str(_resolve_metadata_json(carve_dir))

    dump_file = getattr(args, "dump_file", None)
    if not dump_file:
        raise FileNotFoundError("Either -carve_dir or -dump_file must be provided.")

    return _load_records_from_dump(dump_file, getattr(args, "memory_map", None)), dump_file


def _classify_records(
    records: Sequence[LoadedImageRecord],
    whitelist: Set[str],
) -> List[ClassifiedImagePath]:
    """Classify all path-backed loaded images against the effective whitelist."""
    classified: List[ClassifiedImagePath] = []

    for record in records:
        identity = record["identity"]
        if not _is_path_identity(identity):
            continue

        normalized_identity = _normalize_path_identity(identity)
        if normalized_identity in whitelist:
            status = "allowed"
            reason = "exact whitelist match"
        elif "boot" in Path(normalized_identity).name.lower():
            status = "suspicious"
            reason = "boot-like path is not whitelisted"
        else:
            status = "suspicious"
            reason = "path-backed image is not whitelisted"

        classified.append(
            {
                "image_base": record["image_base"],
                "image_end": record["image_end"],
                "identity": identity,
                "normalized_identity": normalized_identity,
                "status": status,
                "reason": reason,
            }
        )

    return classified


def _render_report(
    source_label: str,
    whitelist: Set[str],
    classified: Sequence[ClassifiedImagePath],
) -> str:
    """Render the path-loading classification report."""
    lines: List[str] = []
    lines.append("Suspicious image loading analysis")
    lines.append(f"Source: {source_label}")
    lines.append(f"Effective whitelist entries: {len(whitelist)}")

    if whitelist:
        lines.append("Whitelisted paths:")
        for path_value in sorted(whitelist):
            lines.append(f"  {path_value}")

    if not classified:
        lines.append("")
        lines.append("No path-backed loaded images were identified.")
        return "\n".join(lines) + "\n"

    suspicious_count = sum(1 for record in classified if record["status"] == "suspicious")
    allowed_count = len(classified) - suspicious_count
    lines.append("")
    lines.append(f"Path-backed images: {len(classified)} total")
    lines.append(f"Allowed: {allowed_count}")
    lines.append(f"Suspicious: {suspicious_count}")
    lines.append("")

    for record in classified:
        lines.append(
            f"[{record['status'].upper()}] 0x{record['image_base']:016X}-0x{record['image_end']:016X} "
            f"{record['identity']}"
        )
        lines.append(f"  normalized: {record['normalized_identity']}")
        lines.append(f"  reason: {record['reason']}")

    return "\n".join(lines) + "\n"


def _write_report(report_text: str, output_path: Optional[str]) -> None:
    """Print the report and optionally append it to an output file."""
    print(report_text)
    if output_path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(report_text)


def run(args) -> None:
    """Execute the suspicious image-load path analysis."""
    records, source_label = _load_records(args)
    whitelist = _build_effective_whitelist(
        getattr(args, "whitelist_path", None),
        getattr(args, "whitelist_file", None),
    )
    classified = _classify_records(records, whitelist)
    report_text = _render_report(source_label, whitelist, classified)
    _write_report(report_text, getattr(args, "output", None) or str(DEFAULT_REPORT_PATH))


plugin_info = {
    "name": "Image Load Path Detection",
    "description": (
        "Identify path-backed loaded images whose exact paths are not present in the configured whitelist."
    ),
    "arguments": [
        {
            "name": "-dump_file",
            "help": "Memory dump file to analyze. Required unless -carve_dir is provided.",
            "required": False,
        },
        {
            "name": "-memory_map",
            "help": "Optional Memory_Map.txt used when extracting image metadata from -dump_file.",
            "required": False,
        },
        {
            "name": "-carve_dir",
            "help": "uefi_image_carving output directory or direct images.json path. Required unless -dump_file is provided.",
            "required": False,
        },
        {
            "name": "-whitelist_path",
            "help": "Exact image path to allow; may be repeated or passed as a comma-separated list. Matching is exact after path normalization.",
            "required": False,
            "action": "append",
        },
        {
            "name": "-whitelist_file",
            "help": "Text file with one exact allowed path per line.",
            "required": False,
        },
        {
            "name": "-output",
            "help": "Optional report file path (default artifacts/reports/image_load_path_report.txt). Results are also printed to stdout.",
            "required": False,
        },
    ],
}
