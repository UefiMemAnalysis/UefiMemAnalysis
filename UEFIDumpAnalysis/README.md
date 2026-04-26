# UEFIDumpAnalysis

`UEFIDumpAnalysis` is a plugin-based toolkit for carving UEFI images from memory
dumps and analyzing common firmware-memory redirection patterns, including:

- EFI service-table pointer hooking
- inline and trampoline control-flow redirection
- gadget-chain resolution against carved images
- suspicious image loading from unexpected filesystem paths

The toolkit is primarily operated from the command line and is intended for research and forensic triage.

## Components

- `uefi_mem_analysis.py`: local compatibility wrapper for the packaged CLI
- `uefi_dump_analysis/cli/`: packaged CLI entrypoint package that discovers analysis modules
- `uefi_dump_analysis/modules/uefi_image_carving.py`: carves loaded binaries and emits their associated metadata
- `uefi_dump_analysis/modules/pointer_hooking_detection.py`: checks EFI service-table pointers for suspicious redirection
- `uefi_dump_analysis/modules/inline_hooking_detection.py`: analyzes control-flow redirection to detect inline and trampoline hooks
- `uefi_dump_analysis/modules/gadget_detection.py`: resolves gadget candidates against carved images and `ropper` output
- `uefi_dump_analysis/modules/image_load_path_detection.py`: flags non-whitelisted path-backed loaded images
- `uefi_dump_analysis/utilities/`: shared dump parsing, address translation, and table helpers

## Installation

`UEFIDumpAnalysis` requires Python 3.10 or later.

Examples below assume your current working directory is `UEFIDumpAnalysis/`.
Paths such as `path/to/dump.bin` are placeholders for local files; sample dumps
are not included in the public repository.
The `artifacts/` paths shown in examples are generated local outputs and are
intentionally ignored by Git.

Base install:

```bash
python -m pip install -e .
```

After installation, you can run the CLI as:

```bash
uefi-mem-analysis -h
```

Gadget-analysis install:

```bash
python -m pip install -e ".[gadget]"
```

`gadget_detection` invokes the pip-installed `ropper` package through
`python -m ropper`, so it does not depend on a hardcoded `ropper.exe` path.
The project pins `capstone` to the 5.x line so the local analyzers and `ropper`
stay on the same major disassembly version.

## Quick Setup

Minimal setup:

```bash
python -m pip install -e .
python -m uefi_dump_analysis -h
```

Enable the gadget plugin as well:

```bash
python -m pip install -e ".[gadget]"
python -m uefi_dump_analysis gadget_detection -h
```

The repository does not include memory dumps. After acquiring or adding a local
dump and memory map, run the carving pipeline with your local paths:

```bash
python -m uefi_dump_analysis uefi_image_carving \
  -f path/to/dump.bin \
  -memory_map path/to/Memory_Map.txt \
  -o artifacts/carved-images/run-name \
  -extract_binaries
```

## Usage

List available modules:

```bash
python -m uefi_dump_analysis -h
```

Installed-command equivalent:

```bash
uefi-mem-analysis -h
```

Show module-specific help:

```bash
python -m uefi_dump_analysis <module> -h
```

Compatibility-wrapper equivalent:

```bash
python uefi_mem_analysis.py <module> -h
```

### uefi_image_carving

Carve loaded binaries from a dump and emit their metadata:

```bash
python -m uefi_dump_analysis uefi_image_carving \
  -f path/to/dump.bin \
  -o artifacts/carved-images/run-name \
  -memory_map path/to/Memory_Map.txt \
  -verify path/to/ImageList.txt \
  -extract_binaries
```

Binary carving is the intended workflow. Metadata-only output exists only as a
fallback when runtime-to-file translation is unavailable.

Arguments:

- `-f`: required raw dump path.
- `-o`: required output directory for `images.csv`, `images.json`, and optionally carved binaries.
- `-memory_map`: optional `Memory_Map.txt` from the dumper. In practice this is required for reliable binary carving because it translates runtime addresses into dump offsets.
- `-extract_binaries`: writes carved binaries under `<output>/images`. Without `-memory_map`, the module falls back to metadata-only output.
- `-verify`: optional dumper-produced `ImageList*.txt`. The dumper's image-list text contains image address ranges and GUID/path identities; this flag only compares the carved results against that list and does not change carving behavior.
- `-debug`: prints detailed carving diagnostics, including signature-hit counts, structure-filter rejection counts, dominant system-table selection, deduplication, and binary-extraction skip reasons.

### pointer_hooking_detection

Check for service-table pointer hooks:

```bash
python -m uefi_dump_analysis pointer_hooking_detection \
  -f path/to/dump.bin \
  -memory_map path/to/Memory_Map.txt \
  -require_valid_crc \
  -o artifacts/reports/pointer_hooks.txt
```

Arguments:

- `-f`: required raw dump path.
- `-memory_map`: optional `Memory_Map.txt`. Strongly recommended for non-identity dumps so pointer targets can be classified against the correct image ranges.
- `-bootservicestable`, `-runtimeservicestable`, `-dxeservicestable`: optional table selectors. If none are provided, the module analyzes all three table classes.
- `-require_valid_crc`: restricts analysis to candidate tables whose header CRC32 field is non-zero.
- `-debug`: prints the loaded-image ranges used for classification.
- `-o`: optional report file. Results are always printed to stdout.

### inline_hooking_detection

Check for inline or trampoline hooks:

```bash
python -m uefi_dump_analysis inline_hooking_detection \
  -f path/to/dump.bin \
  -memory_map path/to/Memory_Map.txt \
  -require_valid_crc \
  -o artifacts/reports/inline_hooks.txt
```

Arguments:

- `-f`: required raw dump path.
- `-memory_map`: optional `Memory_Map.txt`. Strongly recommended for non-identity dumps because disassembly targets are resolved through runtime-to-file translation.
- `-bootservicestable`, `-runtimeservicestable`, `-dxeservicestable`: optional table selectors. If none are provided, the module analyzes all three table classes.
- `-require_valid_crc`: restricts analysis to candidate tables whose header CRC32 field is non-zero.
- `-debug`: prints loaded-image and executable-range summaries used during classification.
- `-o`: optional report file. Results are always printed to stdout.

### gadget_detection

Resolve gadget chains from carved images:

```bash
python -m uefi_dump_analysis gadget_detection \
  -efi_dir artifacts/carved-images/run-name \
  -gadgets_dir artifacts/gadgets/run-name \
  -candidate_dir artifacts/carved-images/run-name \
  -generate_gadgets \
  -output artifacts/reports/gadget_detection_report.txt
```

Run gadget detection directly from a dump:

```bash
python -m uefi_dump_analysis gadget_detection \
  -dump_file path/to/dump.bin \
  -memory_map path/to/Memory_Map.txt \
  -verify path/to/ImageList.txt \
  -carve_output_dir artifacts/carved-images/run-name \
  -gadgets_dir artifacts/gadgets/run-name \
  -generate_gadgets \
  -output artifacts/reports/gadget_detection_report.txt
```

When `-dump_file` is used, the module first carves analysis images through
`uefi_image_carving` with binary extraction enabled. In that flow, `-memory_map`
is usually required to produce the carved binaries that `ropper` runs on.

Arguments:

- `-efi_dir`: directory containing carved analysis images, or a `uefi_image_carving` output directory. Required unless `-dump_file` is used.
- `-dump_file`: raw dump to carve before gadget analysis. Required unless `-efi_dir` is used.
- `-memory_map`: optional `Memory_Map.txt` used when carving from `-dump_file`. Needed for reliable binary extraction.
- `-verify`: optional dumper-produced `ImageList*.txt` forwarded to the carving step. It is used only to compare carved image records against the dumper's image list.
- `-carve_output_dir`: output directory used for auto-carving when `-dump_file` is supplied.
- `-gadgets_dir`: directory holding `*.gadgets.txt` files. If omitted for carved runs, a run-specific directory under `artifacts/gadgets/` is used.
- `-candidates`: comma-separated or space-separated candidate values supplied directly on the command line.
- `-candidate_file`: file with one candidate value per line.
- `-candidate_dir`: directory of candidate images to scan, or a `uefi_image_carving` output directory.
- `-candidate_stride`: byte stride used while scanning candidate images. Default: `8`.
- `-image_base`: default runtime base to assume when resolving provider-image gadget addresses.
- `-image_base_map`: JSON file mapping image file names to runtime base addresses.
- `-min_chain_length`: minimum consecutive gadget count required before a sequence is reported as a chain. Default: `4`.
- `-max_gadget_bytes`: maximum byte window re-disassembled for each gadget during validation. Default: `32`.
- `-skip_capstone_validation`: skips the local Capstone re-disassembly pass and trusts the parsed `ropper` output.
- `-generate_gadgets`: generates missing gadget caches with `python -m ropper`.
- `-ropper_arch`: architecture string passed to `ropper` when gadget files are generated. Default: `x86_64`.
- `-debug`: prints gadget-index and candidate-scan diagnostics, including per-image inspection counts and scan configuration details.
- `-output`: optional report file. Default: `artifacts/reports/gadget_detection_report.txt`.
- `-offsets_mode`: interprets candidate values as gadget offsets rather than runtime addresses.

### image_load_path_detection

Check for suspicious path-backed image loads:

```bash
python -m uefi_dump_analysis image_load_path_detection \
  -dump_file path/to/dump.bin \
  -memory_map path/to/Memory_Map.txt \
  -whitelist_file path/to/allowed_paths.txt \
  -output artifacts/reports/image_load_paths.txt
```

The path-loading module only treats exact whitelisted paths as expected. A
path that merely contains `boot` is still reported as suspicious unless it is
explicitly allowed.

Arguments:

- `-dump_file`: raw dump to analyze. Required unless `-carve_dir` is used.
- `-memory_map`: optional `Memory_Map.txt` used when extracting image metadata from `-dump_file`.
- `-carve_dir`: existing `uefi_image_carving` output directory, or a direct `images.json` path. Required unless `-dump_file` is used.
- `-whitelist_path`: exact path to allow. May be repeated or passed as a comma-separated list. Matching is exact after path normalization.
- `-whitelist_file`: text file containing one exact allowed path per line.
- `-output`: optional report file. Default: `artifacts/reports/image_load_path_report.txt`.

## Expected Inputs

- `dump.bin`: raw dump generated by the accompanying capture tooling
- `Memory_Map.txt`: optional runtime-address translation map used whenever a module needs to convert runtime addresses into dump offsets
- `ImageList*.txt`: optional dumper-generated image list containing loaded-image address ranges together with GUID/path identity data. Used by `uefi_image_carving -verify` and forwarded by `gadget_detection`; it is not required for analysis.

## Outputs

Generated files are written under `artifacts/` by default:

- carved binaries together with their metadata
- gadget cache files generated from analysis images
- text reports produced by the analysis plugins

Those directories are intended for local runs and are ignored by the repository.
