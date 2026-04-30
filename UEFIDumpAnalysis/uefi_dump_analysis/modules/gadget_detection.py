"""Resolve gadget candidates against carved provider images and ropper output."""

import importlib.util
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Literal, Optional, Sequence, Tuple, TypedDict, cast

try:
    import capstone as cpt
except ModuleNotFoundError as exc:  # pragma: no cover - defensive guard for missing dep
    raise ImportError(
        "The 'capstone' package is required for the GadgetDetection module. "
        "Install it with 'pip install \"capstone>=5.0.7,<6\"'."
    ) from exc


ARTIFACTS_DIR = Path("artifacts")
DEFAULT_CARVE_OUTPUT_DIR = ARTIFACTS_DIR / "carved-images" / "auto"
DEFAULT_GADGETS_DIR = ARTIFACTS_DIR / "gadgets"
DEFAULT_REPORT_PATH = ARTIFACTS_DIR / "reports" / "gadget_detection_report.txt"


@dataclass
class GadgetMetadata:
    image_path: str
    gadget_offset: int
    mnemonic: str
    gadget_type: str
    disassembly: Optional[str] = None


ResolutionType = Literal["NONE", "SENTINEL", "RUNTIME", "OFFSET", "PREDICTED"]
Classification = Literal["GADGET", "NON_GADGET"]
ScanEntryType = Literal["GADGET", "DATA", "UNKNOWN"]


class ResolutionContext(TypedDict, total=False):
    type: ResolutionType
    metadata: Optional[GadgetMetadata]
    base: int
    predicted_offset: int


class CandidateResolution(TypedDict):
    value: int
    classification: Classification
    metadata: Optional[GadgetMetadata]
    resolution: ResolutionContext


class ManualChain(TypedDict):
    start: int
    end: int
    sequence: List[CandidateResolution]


class ScanEntry(TypedDict, total=False):
    offset: int
    value: int
    value_hex: str
    type: ScanEntryType
    metadata: Optional[GadgetMetadata]
    disasm_ok: bool
    resolution: ResolutionContext


class ChainSummary(TypedDict):
    total_entries: int
    gadget_count: int
    unknown_count: int
    data_count: int
    disasm_bad_count: int
    score: float
    top_provider: Optional[str]
    provider_ratio: float


class CandidateChain(TypedDict):
    start_offset: int
    end_offset: int
    entries: List[ScanEntry]
    summary: ChainSummary
    original_sequence: List[str]
    resolved_sequence: List[str]


class CandidateImageScan(TypedDict):
    chains: List[CandidateChain]
    inspected_values: List[Tuple[int, int]]


class CandidateImageReport(TypedDict):
    image_path: str
    chains: List[CandidateChain]
    inspected_values: List[Tuple[int, int]]
    stride: int


def resolve_analysis_input_dir(path_value: str, label: str) -> Path:
    """Normalize a CLI directory argument to the directory holding EFI images."""
    path = Path(path_value)
    if not path.exists():
        raise FileNotFoundError(f"{label} not found: {path}")
    if not path.is_dir():
        raise NotADirectoryError(f"{label} is not a directory: {path}")

    images_subdir = path / "images"
    if images_subdir.is_dir():
        return images_subdir

    if (path / "images.json").exists() or (path / "images.csv").exists():
        raise FileNotFoundError(
            f"{label} points to a carving output directory, but '{images_subdir}' is missing. "
            "Re-run image carving with -extract_binaries."
        )

    return path


def carve_provider_images(
    dump_path: str,
    output_dir: str,
    memory_map_path: Optional[str] = None,
    verify_path: Optional[str] = None,
) -> Path:
    """Carve provider images from a dump and return the extracted image directory."""
    from uefi_dump_analysis.modules import uefi_image_carving

    result = uefi_image_carving.carve_images(
        dump_path=dump_path,
        output_dir=output_dir,
        memory_map_path=memory_map_path,
        verify_path=verify_path,
        extract_binaries=True,
    )
    image_dir_value = result.get("image_dir")
    if not image_dir_value:
        raise RuntimeError(
            "Image carving did not produce extracted binaries. Provide -memory_map so runtime "
            "addresses can be translated and binaries can be dumped."
        )
    image_dir = Path(cast(str, image_dir_value))
    if not image_dir.exists():
        raise FileNotFoundError(
            f"Carving completed, but the extracted image directory was not created: {image_dir}"
        )
    return image_dir


def enumerate_efi_images(efi_dir: Path) -> List[Path]:
    """Return provider-image files beneath ``efi_dir``."""
    efi_images: List[Path] = []
    for pattern in ("*.efi", "*.bin", "*.img"):
        efi_images.extend(path for path in efi_dir.glob(pattern) if path.is_file())
    return sorted({path for path in efi_images})


def enumerate_candidate_images(candidate_dir: Path) -> List[Path]:
    """Return candidate-image files beneath ``candidate_dir``."""
    candidates: List[Path] = []
    for pattern in ("*.efi", "*.bin", "*.img"):
        candidates.extend(candidate_dir.glob(pattern))
    return sorted({path for path in candidates if path.is_file()})


def derive_gadget_path(image_path: Path, gadgets_dir: Path) -> Path:
    """Return the gadget-cache path associated with ``image_path``."""
    return gadgets_dir / f"{image_path.name}.gadgets.txt"


def parse_gadget_type(mnemonic: str) -> str:
    """Collapse a gadget mnemonic into a coarse transfer category."""
    instructions = [token.strip().lower() for token in mnemonic.split(";") if token.strip()]
    if not instructions:
        return "UNKNOWN"

    last = instructions[-1]
    if last.startswith("ret"):
        return "RET"
    if last.startswith("jmp"):
        return "JMP"
    if last.startswith("call"):
        return "CALL"
    return "OTHER"


def _read_text_file_with_fallback(path: Path) -> str:
    """
    Read bytes from path and attempt to decode with common encodings.
    Prefer utf-8-sig, utf-8, then utf-16 (which handles BOM), utf-16-le, then latin-1.
    This makes the parser robust to files saved as UTF-16-LE.
    """
    raw = path.read_bytes()
    for enc in ("utf-8-sig", "utf-8", "utf-16", "utf-16-le", "latin-1"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    # Fallback: decode ignoring errors
    return raw.decode("utf-8", errors="ignore")


def parse_gadget_file(gadget_file: Path) -> List[Tuple[int, str]]:
    """Parse a ropper output file into ``(offset, mnemonic)`` entries."""
    parsed: List[Tuple[int, str]] = []
    if not gadget_file.exists():
        return parsed

    # Read with encoding fallback to support UTF-16-LE gadget files
    text = _read_text_file_with_fallback(gadget_file)
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if ":" not in stripped:
            continue
        address_str, mnemonic = stripped.split(":", 1)
        try:
            offset = int(address_str, 0)
        except ValueError:
            continue
        parsed.append((offset, mnemonic.strip()))
    return parsed


def load_image_base_overrides(base_map_path: Optional[str]) -> Dict[str, int]:
    """Load explicit runtime base overrides from a JSON mapping file."""
    if not base_map_path:
        return {}
    path = Path(base_map_path)
    if not path.exists():
        return {}
    # Read and parse JSON using robust decoding
    try:
        text = _read_text_file_with_fallback(path)
        data = json.loads(text)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    overrides: Dict[str, int] = {}
    for key, value in data.items():
        try:
            overrides[key.lower()] = int(value, 0)
        except (ValueError, TypeError):
            continue
    return overrides


def resolve_image_base(image_path: Path, overrides: Dict[str, int], default_base: Optional[int]) -> int:
    """Return the runtime base to use for a provider image."""
    key = image_path.name.lower()
    if key in overrides:
        return overrides[key]
    return default_base or 0


def resolve_image_base_with_source(
    image_path: Path,
    overrides: Dict[str, int],
    default_base: Optional[int],
) -> Tuple[int, str]:
    """Return the runtime base together with the source used to resolve it."""
    key = image_path.name.lower()
    if key in overrides:
        return overrides[key], "image_base_map"
    if default_base is not None:
        return default_base, "image_base"
    return 0, "none"


def load_candidate_addresses(values: List[str]) -> List[int]:
    """Parse candidate-address CLI values into integers."""
    candidates: List[int] = []
    for raw in values:
        if not raw:
            continue
        for token in raw.replace(",", " ").split():
            try:
                candidates.append(int(token, 0))
            except ValueError:
                continue
    return candidates


def resolve_ropper_command() -> List[str]:
    """Return a command that invokes the pip-installed ``ropper`` module."""
    if importlib.util.find_spec("ropper") is None:
        raise RuntimeError(
            "Ropper is not installed in this Python environment. Install it with "
            "'python -m pip install ropper' or 'python -m pip install -e \".[gadget]\"'."
        )
    return [sys.executable, "-m", "ropper"]


def _summarize_ropper_failure(exc: subprocess.CalledProcessError) -> str:
    """Return the most useful single-line Ropper failure message."""
    output = exc.stderr or exc.stdout or ""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if lines:
        return lines[-1]
    return f"exit code {exc.returncode}"


def _run_ropper(
    command: List[str],
    image_path: Path,
    ropper_arch: str,
    env: Dict[str, str],
    *,
    raw_mode: bool,
) -> subprocess.CompletedProcess[str]:
    """Run Ropper for one image and return the completed process."""
    ropper_args = command + ["--arch", ropper_arch, "--file", str(image_path), "--nocolor"]
    if raw_mode:
        ropper_args.insert(len(command), "--raw")

    return subprocess.run(
        ropper_args,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )


def run_ropper_for_image(
    image_path: Path,
    output_path: Path,
    ropper_arch: str = "x86_64",
    raw_mode: bool = False,
    raw_fallback: bool = True,
) -> None:
    """Generate a gadget listing for one image with the pip-installed ropper package."""
    command = resolve_ropper_command()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    cache_home = output_path.parent / ".ropper-home"
    cache_home.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["HOME"] = str(cache_home)
    env["USERPROFILE"] = str(cache_home)
    env["XDG_CACHE_HOME"] = str(cache_home)
    try:
        completed = _run_ropper(
            command,
            image_path,
            ropper_arch,
            env,
            raw_mode=raw_mode,
        )
    except subprocess.CalledProcessError as exc:
        primary_error = _summarize_ropper_failure(exc)
        if raw_mode or not raw_fallback:
            raise RuntimeError(f"Ropper failed for '{image_path}': {primary_error}") from exc

        try:
            completed = _run_ropper(
                command,
                image_path,
                ropper_arch,
                env,
                raw_mode=True,
            )
        except subprocess.CalledProcessError as raw_exc:
            raw_error = _summarize_ropper_failure(raw_exc)
            raise RuntimeError(
                f"Ropper failed for '{image_path}' in PE mode ({primary_error}) "
                f"and raw mode ({raw_error})"
            ) from raw_exc

        print(
            f"Warning: Ropper PE loading failed for '{image_path}' "
            f"({primary_error}); generated gadgets in raw mode."
        )
    output_path.write_text(completed.stdout, encoding="utf-8", newline="\n")


def ensure_gadget_files(
    efi_images: Sequence[Path],
    gadgets_dir: Path,
    *,
    generate_missing: bool,
    ropper_arch: str = "x86_64",
    ropper_raw: bool = False,
) -> List[Path]:
    """Ensure gadget-cache files exist for the supplied provider images."""
    gadgets_dir.mkdir(parents=True, exist_ok=True)
    missing: List[Path] = []

    for image_path in efi_images:
        gadget_file = derive_gadget_path(image_path, gadgets_dir)
        if gadget_file.exists():
            try:
                cache_size = gadget_file.stat().st_size
            except OSError as exc:
                print(f"Warning: Unable to inspect gadget cache '{gadget_file}': {exc}")
                missing.append(image_path)
                continue
            if cache_size > 0:
                continue
            if not generate_missing:
                print(
                    f"Warning: Ignoring empty gadget cache '{gadget_file}'. "
                    "Regenerate it with -generate_gadgets."
                )
                missing.append(image_path)
                continue
        if not generate_missing:
            missing.append(image_path)
            continue
        try:
            run_ropper_for_image(
                image_path,
                gadget_file,
                ropper_arch=ropper_arch,
                raw_mode=ropper_raw,
            )
        except (OSError, RuntimeError) as exc:
            print(f"Warning: {exc}")
            missing.append(image_path)

    return missing


def count_available_gadget_files(efi_images: Sequence[Path], gadgets_dir: Path) -> int:
    """Count non-empty gadget-cache files available for the supplied images."""
    count = 0
    for image_path in efi_images:
        gadget_file = derive_gadget_path(image_path, gadgets_dir)
        if gadget_file.exists() and gadget_file.stat().st_size > 0:
            count += 1
    return count


def validate_with_capstone(
    md: "cpt.Cs",
    image_bytes: bytes,
    gadget_offset: int,
    max_bytes: int,
) -> Optional[str]:
    """Re-disassemble gadget bytes and return the first matching instruction sequence."""
    if gadget_offset >= len(image_bytes):
        return None
    code_slice = image_bytes[gadget_offset : gadget_offset + max_bytes]
    if not code_slice:
        return None

    disassembly: List[str] = []
    for idx, instruction in enumerate(md.disasm(code_slice, gadget_offset)):
        if instruction.mnemonic:
            disassembly.append(f"{instruction.mnemonic} {instruction.op_str}".strip())
        if instruction.mnemonic.startswith("ret") or idx >= 9:
            break
    return "; ".join(disassembly) if disassembly else None


def build_gadget_map(
    efi_images: List[Path],
    gadgets_dir: Path,
    base_overrides: Dict[str, int],
    default_image_base: Optional[int],
    max_gadget_bytes: int,
    skip_capstone_validation: bool,
) -> Tuple[Dict[int, GadgetMetadata], Dict[int, GadgetMetadata], Dict[int, int]]:
    """Build runtime and offset gadget lookup maps for all provider images."""
    gadget_map: Dict[int, GadgetMetadata] = {}
    offset_map: Dict[int, GadgetMetadata] = {}
    # image_bases maps resolved image_base -> image_size (in bytes) for quick checks
    image_bases: Dict[int, int] = {}
    md: Optional["cpt.Cs"] = None

    if not skip_capstone_validation:
        md = cpt.Cs(cpt.CS_ARCH_X86, cpt.CS_MODE_64)
        md.detail = False

    for image_path in efi_images:
        gadget_file = derive_gadget_path(image_path, gadgets_dir)
        if not gadget_file.exists():
            continue

        image_bytes = image_path.read_bytes()
        image_base = resolve_image_base(image_path, base_overrides, default_image_base)
        image_size = len(image_bytes)
        if image_base:
            image_bases[image_base] = image_size

        for gadget_offset, mnemonic in parse_gadget_file(gadget_file):
            runtime_address = image_base + gadget_offset
            metadata = GadgetMetadata(
                image_path=str(image_path),
                gadget_offset=gadget_offset,
                mnemonic=mnemonic,
                gadget_type=parse_gadget_type(mnemonic),
            )
            if md:
                metadata.disassembly = validate_with_capstone(md, image_bytes, gadget_offset, max_gadget_bytes)
            gadget_map[runtime_address] = metadata
            if gadget_offset not in offset_map:
                offset_map[gadget_offset] = metadata

    return gadget_map, offset_map, image_bases


def _is_sentinel_value(value: int) -> bool:
    """Return ``True`` when a value is a common filler rather than a real pointer."""
    return value == 0 or value == 0xFFFFFFFFFFFFFFFF


def _disassembly_matches_gadget_type(metadata: GadgetMetadata) -> bool:
    """
    Quick heuristic: ensure the disassembly's last instruction aligns with the gadget_type.
    - For 'RET' expect the trailing instruction to start with 'ret'
    - For 'JMP' expect a 'jmp' or similar control-transfer mnemonics
    - For 'CALL' expect a 'call' mnemonic
    - For 'OTHER' or missing disasm be permissive (return True)
    """
    if not metadata or not metadata.disassembly:
        return True
    last_instr = metadata.disassembly.split(";")[-1].strip().lower()
    if not last_instr:
        return True
    # extract mnemonic token
    parts = last_instr.split()
    mnemonic = parts[0] if parts else ""
    if metadata.gadget_type == "RET":
        return mnemonic.startswith("ret")
    if metadata.gadget_type == "JMP":
        return mnemonic.startswith("jmp") or mnemonic.startswith("je") or mnemonic.startswith("jne")
    if metadata.gadget_type == "CALL":
        return mnemonic.startswith("call")
    return True


def resolve_value_with_context(
    value: int,
    gadget_map: Dict[int, GadgetMetadata],
    offset_map: Dict[int, GadgetMetadata],
    image_bases: Optional[Dict[int, int]] = None,
    prefer_offsets: bool = False,
) -> ResolutionContext:
    """
    Resolve a raw 8-byte value and return a context dict containing:
      - 'type': one of 'SENTINEL','RUNTIME','OFFSET','PREDICTED','NONE'
      - 'metadata': GadgetMetadata or None
      - 'base': provider base used for PREDICTED (optional)
      - 'predicted_offset': predicted offset used for PREDICTED (optional)

    prefer_offsets: if True, treat the raw value as an offset first (attacker-prepared buffer mode).
    """
    ctx: ResolutionContext = {"type": "NONE", "metadata": None}
    if _is_sentinel_value(value):
        ctx["type"] = "SENTINEL"
        return ctx

    # 1) If caller prefers offsets, check offset_map first
    if prefer_offsets:
        meta = offset_map.get(value)
        if meta:
            ctx.update({"type": "OFFSET", "metadata": meta})
            return ctx

    # 2) Direct runtime address match
    meta = gadget_map.get(value)
    if meta:
        ctx.update({"type": "RUNTIME", "metadata": meta})
        return ctx

    # 3) Direct offset match (value equals gadget offset)
    meta = offset_map.get(value)
    if meta:
        ctx.update({"type": "OFFSET", "metadata": meta})
        return ctx

    # 4) Try predicted offsets from known image bases
    if image_bases:
        for base, size in image_bases.items():
            # Only consider plausible range
            if value < base or (size and value >= base + size):
                continue
            predicted = value - base
            if predicted == 0:
                continue
            meta = offset_map.get(predicted)
            if meta:
                ctx.update({"type": "PREDICTED", "metadata": meta, "base": base, "predicted_offset": predicted})
                return ctx

    return ctx


# keep existing resolve_value_against_maps for compatibility
def resolve_value_against_maps(
    value: int,
    gadget_map: Dict[int, GadgetMetadata],
    offset_map: Dict[int, GadgetMetadata],
    image_bases: Optional[Dict[int, int]] = None,
) -> Optional[GadgetMetadata]:
    """Return only gadget metadata for callers that use the legacy helper contract."""
    # Backwards compatible wrapper that returns only metadata
    ctx = resolve_value_with_context(value, gadget_map, offset_map, image_bases, prefer_offsets=False)
    return cast(Optional[GadgetMetadata], ctx.get("metadata"))


def resolve_candidate_addresses(
    candidate_addresses: Iterable[int],
    gadget_map: Dict[int, GadgetMetadata],
    offset_map: Dict[int, GadgetMetadata],
    image_bases: Optional[Dict[int, int]] = None,
    prefer_offsets: bool = False,
) -> List[CandidateResolution]:
    """Resolve a sequence of candidate values into classified gadget candidates."""
    results: List[CandidateResolution] = []
    for address in candidate_addresses:
        resolution = resolve_value_with_context(
            address,
            gadget_map,
            offset_map,
            image_bases,
            prefer_offsets=prefer_offsets,
        )
        metadata = cast(Optional[GadgetMetadata], resolution.get("metadata"))
        results.append(
            {
                "value": address,
                "classification": "GADGET" if metadata else "NON_GADGET",
                "metadata": metadata,
                "resolution": resolution,
            }
        )
    return results


def detect_gadget_chains(
    resolutions: List[CandidateResolution],
    min_chain_length: int,
) -> List[ManualChain]:
    """Identify consecutive gadget runs in a manually supplied candidate sequence."""
    chains: List[ManualChain] = []
    start_index: Optional[int] = None

    for idx, entry in enumerate(resolutions):
        is_gadget = entry["classification"] == "GADGET"
        if is_gadget:
            if start_index is None:
                start_index = idx
            continue

        if start_index is not None:
            if idx - start_index >= min_chain_length:
                chains.append(
                    {
                        "start": start_index,
                        "end": idx - 1,
                        "sequence": resolutions[start_index:idx],
                    }
                )
            start_index = None

    if start_index is not None and len(resolutions) - start_index >= min_chain_length:
        chains.append(
            {
                "start": start_index,
                "end": len(resolutions) - 1,
                "sequence": resolutions[start_index:],
            }
        )

    return chains


def scan_candidate_image_for_chains(
    image_path: Path,
    gadget_map: Dict[int, GadgetMetadata],
    offset_map: Dict[int, GadgetMetadata],
    min_chain_length: int,
    stride: int = 8,
    image_bases: Optional[Dict[int, int]] = None,
    allowed_padding_values: Optional[Sequence[int]] = None,
    min_chain_gadgets: Optional[int] = None,
    min_gadget_ratio: float = 0.5,
    candidate_ranges: Optional[Sequence[Tuple[int, int]]] = None,
    max_padding_between_gadgets: int = 3,
    max_unknown_between_gadgets: int = 2,
    require_provider_consistency: bool = False,
    provider_consistency_ratio: float = 0.6,
    scoring_enabled: bool = True,
    scoring_weights: Optional[Dict[str, float]] = None,
    score_threshold: float = 0.4,
    require_disasm_for_count: bool = False,
    candidate_values_are_offsets: bool = False,
) -> CandidateImageScan:
    """
    Scan a candidate image for contiguous chains of gadget pointers and allowed padding.

    When ``candidate_values_are_offsets`` is set, raw 8-byte words are treated
    as gadget offsets rather than runtime addresses.
    """
    if allowed_padding_values is None:
        allowed_padding_values = [0xFFFFFFFFFFFFFFFF]
    allowed_padding_set = set(allowed_padding_values)

    if min_chain_gadgets is None:
        min_chain_gadgets = max(1, min_chain_length // 2)

    # default scoring weights
    if scoring_weights is None:
        scoring_weights = {
            "gadget": 1.0,
            "unknown": -0.4,
            "data": 0.0,
            "disasm_bad": -0.8,
        }

    # Build provider ranges from image_bases
    provider_ranges: List[Tuple[int, int]] = []
    if image_bases:
        for base, size in image_bases.items():
            provider_ranges.append((base, base + (size or 0)))

    # Normalize candidate_ranges into list
    cand_ranges: Optional[List[Tuple[int, int]]] = None
    if candidate_ranges:
        cand_ranges = list(candidate_ranges)

    data = image_path.read_bytes()
    chains: List[CandidateChain] = []
    current_entries: List[ScanEntry] = []
    inspected_values: List[Tuple[int, int]] = []
    padding_run = 0
    unknown_run = 0

    def _compute_run_metrics(run_entries: List[ScanEntry]) -> ChainSummary:
        """Summarize one scanned run for later chain scoring and reporting."""
        total = len(run_entries)
        gadget_count = 0
        disasm_bad_count = 0
        unknown_count = 0
        data_count = 0
        provider_counts: Dict[str, int] = {}

        for e in run_entries:
            t = e.get("type")
            if t == "GADGET":
                meta = e.get("metadata")
                disasm_ok = True
                if meta:
                    disasm_ok = _disassembly_matches_gadget_type(meta)
                    provider_counts[meta.image_path] = provider_counts.get(meta.image_path, 0) + 1
                # respect require_disasm_for_count
                if require_disasm_for_count and not disasm_ok:
                    disasm_bad_count += 1
                else:
                    gadget_count += 1
            elif t == "UNKNOWN":
                unknown_count += 1
            else:
                data_count += 1

        # compute score
        w_g = scoring_weights.get("gadget", 1.0)
        w_u = scoring_weights.get("unknown", -0.4)
        w_d = scoring_weights.get("data", 0.0)
        w_db = scoring_weights.get("disasm_bad", -0.8)

        weighted_sum = (gadget_count * w_g) + (unknown_count * w_u) + (data_count * w_d)
        weighted_sum += disasm_bad_count * w_db
        score = weighted_sum / total if total > 0 else 0.0

        top_provider = None
        provider_ratio = 0.0
        if provider_counts and sum(provider_counts.values()) > 0:
            top_provider, top_count = max(provider_counts.items(), key=lambda kv: kv[1])
            provider_ratio = top_count / sum(provider_counts.values())

        return {
            "total_entries": total,
            "gadget_count": gadget_count,
            "unknown_count": unknown_count,
            "data_count": data_count,
            "disasm_bad_count": disasm_bad_count,
            "score": score,
            "top_provider": top_provider,
            "provider_ratio": provider_ratio,
        }

    def _evaluate_and_maybe_append(run_entries: List[ScanEntry]) -> None:
        """Append a scanned run when it satisfies the gadget-chain thresholds."""
        metrics = _compute_run_metrics(run_entries)
        total = metrics["total_entries"]
        gadget_count = metrics["gadget_count"]
        score = metrics["score"]

        if total < min_chain_length or gadget_count < min_chain_gadgets or (gadget_count / total) < min_gadget_ratio:
            return
        if scoring_enabled and score < score_threshold:
            return
        # optional provider consistency
        if require_provider_consistency and gadget_count > 0:
            provider_ratio = metrics["provider_ratio"]
            if provider_ratio < provider_consistency_ratio:
                return

        # Build original_sequence and resolved_sequence for the run
        original_sequence = [f"0x{e['value']:016x}" for e in run_entries]
        resolved_sequence: List[str] = []
        for e in run_entries:
            res = e["resolution"]
            rtype = res.get("type")
            if rtype == "RUNTIME":
                md = e["metadata"]
                if not md:
                    resolved_sequence.append("UNKNOWN")
                    continue
                resolved_sequence.append(f"RUNTIME -> {md.image_path}:+0x{md.gadget_offset:x}")
            elif rtype == "OFFSET":
                md = e["metadata"]
                if not md:
                    resolved_sequence.append("UNKNOWN")
                    continue
                resolved_sequence.append(f"OFFSET -> {md.image_path}:+0x{md.gadget_offset:x}")
            elif rtype == "PREDICTED":
                md = e["metadata"]
                if not md:
                    resolved_sequence.append("UNKNOWN")
                    continue
                base = res.get("base")
                pred = res.get("predicted_offset")
                resolved_sequence.append(f"PREDICTED(base=0x{base:x}) -> {md.image_path}:+0x{pred:x}")
            elif rtype == "SENTINEL":
                resolved_sequence.append("SENTINEL")
            elif e["type"] == "DATA":
                resolved_sequence.append("DATA")
            else:
                resolved_sequence.append("UNKNOWN")

        chains.append(
            {
                "start_offset": run_entries[0]["offset"],
                "end_offset": run_entries[-1]["offset"],
                "entries": run_entries[:],
                "summary": metrics,
                "original_sequence": original_sequence,
                "resolved_sequence": resolved_sequence,
            }
        )

    for offset in range(0, len(data) - stride + 1, stride):
        chunk = data[offset : offset + stride]
        value = int.from_bytes(chunk, "little")
        inspected_values.append((offset, value))

        # resolve with context; prefer offsets if candidate_values_are_offsets=True
        ctx = resolve_value_with_context(value, gadget_map, offset_map, image_bases, prefer_offsets=candidate_values_are_offsets)
        metadata = cast(Optional[GadgetMetadata], ctx.get("metadata"))
        rtype = ctx.get("type")

        if metadata and rtype in ("RUNTIME", "OFFSET", "PREDICTED"):
            disasm_ok = _disassembly_matches_gadget_type(metadata)
            entry: ScanEntry = {
                "offset": offset,
                "value": value,
                "value_hex": f"0x{value:016x}",
                "type": "GADGET",
                "metadata": metadata,
                "disasm_ok": disasm_ok,
                "resolution": ctx,
            }
            current_entries.append(entry)
            padding_run = 0
            unknown_run = 0
            continue

        # If value equals explicit allowed padding -> treat as DATA and part of run
        if value in allowed_padding_set or _is_sentinel_value(value):
            entry: ScanEntry = {
                "offset": offset,
                "value": value,
                "value_hex": f"0x{value:016x}",
                "type": "DATA",
                "metadata": None,
                "resolution": ctx,
            }
            current_entries.append(entry)
            padding_run += 1
            unknown_run = 0
            # if padding run exceeds max allowed gap, treat as hard break (evaluate run)
            if padding_run > max_padding_between_gadgets:
                _evaluate_and_maybe_append(current_entries)
                current_entries = []
                padding_run = 0
            continue

        # Value not resolved and not explicit padding. Determine if it's a plausible address.
        in_candidate = _value_in_any_range(value, cand_ranges)
        in_provider = _value_in_any_range(value, provider_ranges)

        if not in_candidate and not in_provider:
            # This is a "nop-like" value (not a plausible address for either image) -> treat as DATA
            entry = {
                "offset": offset,
                "value": value,
                "value_hex": f"0x{value:016x}",
                "type": "DATA",
                "metadata": None,
                "resolution": ctx,
            }
            current_entries.append(entry)
            padding_run += 1
            unknown_run = 0
            if padding_run > max_padding_between_gadgets:
                _evaluate_and_maybe_append(current_entries)
                current_entries = []
                padding_run = 0
            continue

        # Otherwise, value looks like an address (in candidate or provider) but didn't resolve -> treat as UNKNOWN
        entry = {
            "offset": offset,
            "value": value,
            "value_hex": f"0x{value:016x}",
            "type": "UNKNOWN",
            "metadata": None,
            "resolution": ctx,
        }
        current_entries.append(entry)
        unknown_run += 1
        padding_run = 0
        # if too many consecutive unknowns, treat as hard break
        if unknown_run > max_unknown_between_gadgets:
            _evaluate_and_maybe_append(current_entries)
            current_entries = []
            unknown_run = 0
            padding_run = 0
            continue

    # End of file: evaluate remaining run
    if current_entries:
        _evaluate_and_maybe_append(current_entries)

    return {"chains": chains, "inspected_values": inspected_values}


def scan_candidate_images(
    candidate_dir: Path,
    gadget_map: Dict[int, GadgetMetadata],
    offset_map: Dict[int, GadgetMetadata],
    min_chain_length: int,
    stride: int = 8,
    image_bases: Optional[Dict[int, int]] = None,
    candidate_values_are_offsets: bool = False,
    min_gadget_ratio: float = 0.5,
    score_threshold: float = 0.4,
    max_padding_between_gadgets: int = 3,
    max_unknown_between_gadgets: int = 2,
    require_provider_consistency: bool = False,
    provider_consistency_ratio: float = 0.6,
) -> List[CandidateImageReport]:
    """Scan candidate images for gadget-like address chains."""
    reports: List[CandidateImageReport] = []
    candidate_images = enumerate_candidate_images(candidate_dir)
    for image_path in candidate_images:
        scan_result = scan_candidate_image_for_chains(
            image_path=image_path,
            gadget_map=gadget_map,
            offset_map=offset_map,
            min_chain_length=min_chain_length,
            stride=stride,
            image_bases=image_bases,
            candidate_values_are_offsets=candidate_values_are_offsets,
            min_gadget_ratio=min_gadget_ratio,
            score_threshold=score_threshold,
            max_padding_between_gadgets=max_padding_between_gadgets,
            max_unknown_between_gadgets=max_unknown_between_gadgets,
            require_provider_consistency=require_provider_consistency,
            provider_consistency_ratio=provider_consistency_ratio,
        )
        reports.append(
            {
                "image_path": str(image_path),
                "chains": scan_result["chains"],
                "inspected_values": scan_result["inspected_values"],
                "stride": stride,
            }
        )
    return reports


def render_manual_candidate_results(
    resolutions: Sequence[CandidateResolution],
    chains: Sequence[ManualChain],
) -> str:
    """Render the manual candidate-address analysis report."""
    if not resolutions:
        return "No candidate addresses were provided.\n"

    lines: List[str] = []
    lines.append("Candidate address classification:")
    for idx, entry in enumerate(resolutions):
        value = entry["value"]
        classification = entry["classification"]
        lines.append(f"[{idx}] {value:#018x} -> {classification}")
        metadata = cast(Optional[GadgetMetadata], entry.get("metadata"))
        if metadata:
            lines.append(
                f"    image={metadata.image_path}, offset=0x{metadata.gadget_offset:x}, "
                f"type={metadata.gadget_type}, mnemonic={metadata.mnemonic}"
            )
            if metadata.disassembly:
                lines.append(f"    disasm={metadata.disassembly}")

    if chains:
        lines.append("\nDetected gadget chains:")
        for chain in chains:
            lines.append(f"  Chain {chain['start']} - {chain['end']}")
            for sequence_entry in chain["sequence"]:
                metadata = sequence_entry.get("metadata")
                if not metadata:
                    continue
                lines.append(
                    f"    {sequence_entry['value']:#018x} -> "
                    f"{metadata.gadget_type} ({metadata.mnemonic})"
                )
    else:
        lines.append("\nNo chains met the minimum gadget length requirement.")

    return "\n".join(lines) + "\n"


def render_candidate_image_reports(
    reports: Sequence[CandidateImageReport],
    *,
    include_scan_stats: bool = False,
) -> str:
    """Render the per-image gadget-chain scan report."""
    if not reports:
        return ""

    relevant_reports = list(reports)
    if not include_scan_stats:
        relevant_reports = [report for report in reports if report["chains"]]
        if not relevant_reports:
            return ""

    lines: List[str] = []
    lines.append("Candidate image scan results:")
    for report in relevant_reports:
        lines.append(f"\nImage: {report['image_path']}")
        if not report["chains"] and include_scan_stats:
            lines.append("  No gadget chains found.")
        for chain_idx, chain in enumerate(report["chains"], start=1):
            lines.append(
                f"  Chain #{chain_idx} offsets 0x{chain['start_offset']:x} - 0x{chain['end_offset']:x}"
            )
            for entry in chain["entries"]:
                if entry["type"] == "GADGET":
                    metadata = cast(GadgetMetadata, entry["metadata"])
                    lines.append(
                        f"    {entry['value']:#018x} -> {metadata.image_path} "
                        f"(offset 0x{metadata.gadget_offset:x}, {metadata.gadget_type})"
                    )
                    lines.append(f"       mnemonic: {metadata.mnemonic}")
                    if metadata.disassembly:
                        lines.append(f"       disasm: {metadata.disassembly}")
                else:
                    # DATA or UNKNOWN
                    lines.append(f"    {entry['value_hex']} -> {entry.get('type')}")
            # Print original/resolved sequences if present
            if chain["original_sequence"]:
                lines.append("    original_sequence:")
                for s in chain["original_sequence"]:
                    lines.append(f"      {s}")
            if chain["resolved_sequence"]:
                lines.append("    resolved_sequence:")
                for s in chain["resolved_sequence"]:
                    lines.append(f"      {s}")
            # Render chain summary: counts and score
            summary = chain["summary"]
            lines.append(f"    Total: {summary['total_entries']} entries")
            lines.append(f"    Gadgets: {summary['gadget_count']}")
            lines.append(f"    Score: {summary['score']:.4f}")
            top_provider = summary["top_provider"]
            if top_provider:
                lines.append(
                    f"    Top provider: {top_provider} (ratio {summary['provider_ratio']:.2%})"
                )
        if include_scan_stats:
            inspected = report["inspected_values"]
            if inspected:
                sample = ", ".join(
                    f"(off 0x{offset:x} -> {value:#018x})" for offset, value in inspected[:10]
                )
                lines.append(f"  Inspected values sample: {sample}")
                lines.append(f"  Total inspected: {len(inspected)} entries at stride {report['stride']}")
    return "\n".join(lines) + "\n"


def render_gadget_detection_summary(
    efi_images: Sequence[Path],
    candidate_reports: Sequence[CandidateImageReport],
    gadget_file_count: int,
    missing_gadget_images: Sequence[Path],
) -> str:
    """Render a short findings-first summary for the default output path."""
    total_chains = sum(len(report["chains"]) for report in candidate_reports)
    lines = [
        "Gadget detection summary:",
        f"Provider images: {len(efi_images)}",
        f"Gadget caches available: {gadget_file_count}",
        f"Gadget-cache failures or missing files: {len(missing_gadget_images)}",
        f"Candidate images scanned: {len(candidate_reports)}",
        f"Detected candidate chains: {total_chains}",
    ]
    return "\n".join(lines) + "\n"


def render_gadget_detection_debug_report(
    *,
    efi_dir: Path,
    gadgets_dir: Path,
    candidate_dir: Optional[Path],
    output_path: Path,
    efi_images: Sequence[Path],
    candidate_reports: Sequence[CandidateImageReport],
    base_overrides: Dict[str, int],
    default_image_base: Optional[int],
    gadget_map: Dict[int, GadgetMetadata],
    offset_map: Dict[int, GadgetMetadata],
    image_bases: Dict[int, int],
    missing_gadget_images: Sequence[Path],
    gadget_file_count: int,
    min_chain_length: int,
    stride: int,
    offsets_mode: bool,
    ropper_arch: str,
    ropper_raw: bool,
    generate_gadgets: bool,
    skip_capstone_validation: bool,
    max_gadget_bytes: int,
) -> str:
    """Render diagnostic output for the gadget-detection workflow."""
    lines: List[str] = []
    lines.append("[debug] GadgetDetection diagnostics")
    try:
        ropper_command = " ".join(resolve_ropper_command())
    except RuntimeError as exc:
        ropper_command = f"unavailable ({exc})"
    lines.append(f"[debug] ropper_command: {ropper_command}")
    lines.append(f"[debug] efi_dir: {efi_dir}")
    lines.append(f"[debug] gadgets_dir: {gadgets_dir}")
    lines.append(f"[debug] candidate_dir: {candidate_dir if candidate_dir else '<none>'}")
    lines.append(f"[debug] output_path: {output_path}")
    lines.append(
        "[debug] scan_parameters: "
        f"min_chain_length={min_chain_length} "
        f"candidate_stride={stride} "
        f"offsets_mode={offsets_mode} "
        f"ropper_arch={ropper_arch} "
        f"ropper_raw={ropper_raw} "
        f"generate_gadgets={generate_gadgets} "
        f"skip_capstone_validation={skip_capstone_validation} "
        f"max_gadget_bytes={max_gadget_bytes}"
    )
    lines.append(
        "[debug] gadget_index_summary: "
        f"provider_images={len(efi_images)} "
        f"gadget_files_available={gadget_file_count} "
        f"gadget_file_missing_or_failed={len(missing_gadget_images)} "
        f"runtime_entries={len(gadget_map)} "
        f"offset_entries={len(offset_map)} "
        f"provider_image_bases={len(image_bases)}"
    )
    if not skip_capstone_validation:
        disasm_available = sum(1 for metadata in gadget_map.values() if metadata.disassembly)
        disasm_mismatch = sum(
            1 for metadata in gadget_map.values() if metadata.disassembly and not _disassembly_matches_gadget_type(metadata)
        )
        lines.append(
            "[debug] validation_summary: "
            f"validated_gadgets={disasm_available} "
            f"disassembly_mismatches={disasm_mismatch}"
        )

    lines.append("[debug] provider_image_bases:")
    for image_path in efi_images:
        image_base, source = resolve_image_base_with_source(image_path, base_overrides, default_image_base)
        if image_base:
            base_text = f"0x{image_base:016X}"
        else:
            base_text = "<none>"
        lines.append(f"[debug]   {image_path.name}: base={base_text} source={source}")

    if missing_gadget_images:
        lines.append("[debug] missing_or_failed_gadget_images:")
        for image_path in missing_gadget_images:
            lines.append(f"[debug]   {image_path}")

    if candidate_reports:
        total_chains = sum(len(report["chains"]) for report in candidate_reports)
        lines.append(
            "[debug] candidate_scan_summary: "
            f"candidate_images={len(candidate_reports)} "
            f"detected_chains={total_chains}"
        )
        for report in candidate_reports:
            lines.append(
                f"[debug]   image={report['image_path']} "
                f"chains={len(report['chains'])} "
                f"inspected={len(report['inspected_values'])} "
                f"stride={report['stride']}"
            )

    return "\n".join(lines) + "\n"


def read_candidates_from_file(path: Optional[str]) -> List[str]:
    """Read newline-delimited candidate addresses from ``path``."""
    if not path:
        return []
    file_path = Path(path)
    if not file_path.exists():
        return []
    text = _read_text_file_with_fallback(file_path)
    return [line.strip() for line in text.splitlines() if line.strip()]


def _resolve_efi_dir(args) -> Path:
    """Resolve the provider-image directory, carving from a dump when needed."""
    efi_dir_arg = getattr(args, "efi_dir", None)
    if efi_dir_arg:
        return resolve_analysis_input_dir(efi_dir_arg, "EFI directory")

    dump_file = getattr(args, "dump_file", None)
    if not dump_file:
        raise FileNotFoundError("Either -efi_dir or -dump_file must be provided.")

    carve_output_dir = getattr(args, "carve_output_dir", None) or str(DEFAULT_CARVE_OUTPUT_DIR)
    return carve_provider_images(
        dump_path=dump_file,
        output_dir=carve_output_dir,
        memory_map_path=getattr(args, "memory_map", None),
        verify_path=getattr(args, "verify", None),
    )


def _resolve_gadgets_dir(args, efi_dir: Path) -> Path:
    """Resolve the directory that stores gadget-cache files."""
    gadgets_dir_arg = getattr(args, "gadgets_dir", None)
    if gadgets_dir_arg:
        return Path(gadgets_dir_arg)

    if efi_dir.name == "images":
        carved_run_dir = efi_dir.parent
        if carved_run_dir.parent.name == "carved-images":
            return DEFAULT_GADGETS_DIR / carved_run_dir.name
        return carved_run_dir / "gadgets"
    return DEFAULT_GADGETS_DIR


def _resolve_candidate_dir(args, default_dir: Optional[Path]) -> Optional[Path]:
    """Resolve the candidate-image directory when one is requested."""
    candidate_dir_arg = getattr(args, "candidate_dir", None)
    if candidate_dir_arg:
        return resolve_analysis_input_dir(candidate_dir_arg, "Candidate directory")
    return default_dir


def run(args) -> None:
    """Execute gadget detection for manual candidates or candidate-image scans."""
    dump_file = getattr(args, "dump_file", None)
    efi_dir = _resolve_efi_dir(args)
    gadgets_dir = _resolve_gadgets_dir(args, efi_dir)
    candidate_dir = _resolve_candidate_dir(args, efi_dir if dump_file else None)
    output_path = Path(getattr(args, "output", None) or DEFAULT_REPORT_PATH)
    debug_enabled = bool(getattr(args, "debug", False))

    efi_images = enumerate_efi_images(efi_dir)
    if not efi_images:
        print(f"No provider images were found under {efi_dir}")
        return

    base_overrides = load_image_base_overrides(getattr(args, "image_base_map", None))
    default_image_base = None
    if getattr(args, "image_base", None):
        default_image_base = int(args.image_base, 0)

    max_gadget_bytes = int(getattr(args, "max_gadget_bytes", 32) or 32)
    skip_capstone_validation = bool(getattr(args, "skip_capstone_validation", False))
    min_chain_length = int(getattr(args, "min_chain_length", 4) or 4)
    stride = int(getattr(args, "candidate_stride", 8) or 8)
    offsets_mode = bool(getattr(args, "offsets_mode", False))
    ropper_arch = getattr(args, "ropper_arch", None) or "x86_64"
    ropper_raw = bool(getattr(args, "ropper_raw", False))
    generate_gadgets = bool(getattr(args, "generate_gadgets", False) or dump_file)

    missing_gadget_images = ensure_gadget_files(
        efi_images=efi_images,
        gadgets_dir=gadgets_dir,
        generate_missing=generate_gadgets,
        ropper_arch=ropper_arch,
        ropper_raw=ropper_raw,
    )
    if missing_gadget_images:
        print(
            f"Warning: {len(missing_gadget_images)} provider images do not have gadget files under "
            f"{gadgets_dir}. Missing caches and per-image Ropper failures are skipped."
        )

    gadget_map, offset_map, image_bases = build_gadget_map(
        efi_images=efi_images,
        gadgets_dir=gadgets_dir,
        base_overrides=base_overrides,
        default_image_base=default_image_base,
        max_gadget_bytes=max_gadget_bytes,
        skip_capstone_validation=skip_capstone_validation,
    )

    if not gadget_map:
        print("No gadgets were indexed. Ensure gadget files exist beside each EFI image.")
        return

    output_sections: List[str] = []
    gadget_file_count = count_available_gadget_files(efi_images, gadgets_dir)

    candidate_inputs: List[str] = []
    candidate_inputs.extend(getattr(args, "candidates", []) or [])
    candidate_inputs.extend(read_candidates_from_file(getattr(args, "candidate_file", None)))

    candidates = load_candidate_addresses(candidate_inputs)
    if default_image_base and candidates and not offsets_mode:
        candidates = [addr - default_image_base for addr in candidates]

    if candidates:
        resolutions = resolve_candidate_addresses(
            candidates,
            gadget_map,
            offset_map,
            image_bases,
            prefer_offsets=offsets_mode,
        )
        chains = detect_gadget_chains(resolutions, min_chain_length)
        manual_report = render_manual_candidate_results(resolutions, chains)
        print(manual_report)
        output_sections.append(manual_report)
    elif not candidate_dir:
        print("No candidate addresses provided via -candidates or -candidate_file.")

    candidate_reports: List[CandidateImageReport] = []
    if candidate_dir:
        candidate_reports = scan_candidate_images(
            candidate_dir=candidate_dir,
            gadget_map=gadget_map,
            offset_map=offset_map,
            min_chain_length=min_chain_length,
            stride=stride,
            image_bases=image_bases,
            candidate_values_are_offsets=offsets_mode,
        )
        summary_report = render_gadget_detection_summary(
            efi_images=efi_images,
            candidate_reports=candidate_reports,
            gadget_file_count=gadget_file_count,
            missing_gadget_images=missing_gadget_images,
        )
        print(summary_report)
        output_sections.append(summary_report)
        if candidate_reports:
            scan_report = render_candidate_image_reports(candidate_reports)
            if scan_report:
                print(scan_report)
                output_sections.append(scan_report)
            if debug_enabled:
                debug_scan_report = render_candidate_image_reports(
                    candidate_reports,
                    include_scan_stats=True,
                )
                print(debug_scan_report)
                output_sections.append(debug_scan_report)
        else:
            message = f"No gadget chains identified in candidate images under {candidate_dir}."
            print(message)
            output_sections.append(message + "\n")
    elif candidate_inputs:
        summary_report = render_gadget_detection_summary(
            efi_images=efi_images,
            candidate_reports=[],
            gadget_file_count=gadget_file_count,
            missing_gadget_images=missing_gadget_images,
        )
        print(summary_report)
        output_sections.append(summary_report)

    if debug_enabled:
        debug_report = render_gadget_detection_debug_report(
            efi_dir=efi_dir,
            gadgets_dir=gadgets_dir,
            candidate_dir=candidate_dir,
            output_path=output_path,
            efi_images=efi_images,
            candidate_reports=candidate_reports,
            base_overrides=base_overrides,
            default_image_base=default_image_base,
            gadget_map=gadget_map,
            offset_map=offset_map,
            image_bases=image_bases,
            missing_gadget_images=missing_gadget_images,
            gadget_file_count=gadget_file_count,
            min_chain_length=min_chain_length,
            stride=stride,
            offsets_mode=offsets_mode,
            ropper_arch=ropper_arch,
            ropper_raw=ropper_raw,
            generate_gadgets=generate_gadgets,
            skip_capstone_validation=skip_capstone_validation,
            max_gadget_bytes=max_gadget_bytes,
        )
        print(debug_report)
        output_sections.append(debug_report)

    if output_path and output_sections:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("a", encoding="utf-8") as handle:
            handle.write("\n".join(output_sections))


plugin_info = {
    "name": "Gadget Detection",
    "description": (
        "Resolve candidate gadget addresses using Ropper output. Accepts either carved analysis "
        "images or a dump that will be carved automatically before analysis."
    ),
    "arguments": [
        {
            "name": "-efi_dir",
            "help": "Directory with carved analysis images, or a uefi_image_carving output directory. Required unless -dump_file is provided.",
            "required": False,
        },
        {
            "name": "-dump_file",
            "help": "Optional memory dump to carve before analysis when -efi_dir is not provided.",
            "required": False,
        },
        {
            "name": "-memory_map",
            "help": "Memory map used when carving analysis images from -dump_file. Needed for reliable binary extraction.",
            "required": False,
        },
        {
            "name": "-verify",
            "help": (
                "Optional dumper-produced ImageList*.txt file forwarded to the carving step. "
                "Used only to compare carved image records against the dumper's list."
            ),
            "required": False,
        },
        {
            "name": "-carve_output_dir",
            "help": "Output directory for carved analysis images when -dump_file is used (default artifacts/carved-images/auto).",
            "required": False,
        },
        {
            "name": "-gadgets_dir",
            "help": "Directory with *.gadgets.txt files; defaults to artifacts/gadgets/<run-name> for carved outputs.",
            "required": False,
        },
        {
            "name": "-candidates",
            "help": "Comma/space separated list of candidate addresses (hex or decimal).",
            "required": False,
        },
        {
            "name": "-candidate_file",
            "help": "File containing candidate addresses, one per line.",
            "required": False,
        },
        {
            "name": "-candidate_dir",
            "help": "Directory containing candidate images to scan, or a uefi_image_carving output directory.",
            "required": False,
        },
        {
            "name": "-candidate_stride",
            "help": "Stride, in bytes, between candidate address reads (default 8).",
            "required": False,
        },
        {
            "name": "-image_base",
            "help": "Default runtime image base to assume when no per-image override is supplied.",
            "required": False,
        },
        {
            "name": "-image_base_map",
            "help": "JSON file mapping image file names to runtime base addresses.",
            "required": False,
        },
        {
            "name": "-min_chain_length",
            "help": "Minimum consecutive gadgets to treat as a chain (default 4).",
            "required": False,
        },
        {
            "name": "-max_gadget_bytes",
            "help": "Maximum bytes to disassemble per gadget when validating (default 32).",
            "required": False,
        },
        {
            "name": "-skip_capstone_validation",
            "help": "Skip Capstone re-disassembly of gadget bytes after parsing Ropper output.",
            "action": "store_true",
        },
        {
            "name": "-generate_gadgets",
            "help": "Generate missing gadget files with the pip-installed Ropper CLI.",
            "action": "store_true",
        },
        {
            "name": "-ropper_arch",
            "help": "Architecture passed to Ropper when generating gadgets (default x86_64).",
            "required": False,
        },
        {
            "name": "-ropper_raw",
            "help": (
                "Load provider images as raw bytes when generating gadgets. "
                "Useful for memory-layout carved images whose PE metadata cannot be parsed by Ropper."
            ),
            "action": "store_true",
        },
        {
            "name": "-output",
            "help": "Optional file that should receive a copy of the reported evidence (default artifacts/reports/gadget_detection_report.txt).",
            "required": False,
        },
        {
            "name": "-offsets_mode",
            "help": "Treat candidate values as gadget offsets instead of runtime addresses (useful for attacker-prepared buffers).",
            "action": "store_true",
        },
        {
            "name": "-debug",
            "help": "Print gadget-index and candidate-scan diagnostics, including per-image inspection counts.",
            "action": "store_true",
        },
    ],
}


def _value_in_any_range(value: int, ranges: Optional[Sequence[Tuple[int, int]]]) -> bool:
    """Return True if value is within any (start,end) tuple in ranges (start inclusive, end exclusive)."""
    if not ranges:
        return False
    for start, end in ranges:
        if start <= value < end:
            return True
    return False
