# UEFIDumpAnalysis

`UEFIDumpAnalysis` is a plugin-based toolkit for offline analysis of UEFI memory
dumps. It extracts loaded-image metadata and supports detection workflows for:

- EFI service-table pointer hooking
- inline and trampoline control-flow redirection
- gadget-chain resolution against extracted images
- suspicious image loading from unexpected filesystem paths

The toolkit is primarily operated from the command line and is intended for
research and forensic triage.

## Installation

`UEFIDumpAnalysis` requires Python 3.10 through 3.13.

From the `UEFIDumpAnalysis/` directory, install the base package:

```bash
python -m pip install -e .
```

This installs the `uefi-mem-analysis` console command. The examples below use
`python -m uefi_dump_analysis`; after installation, `uefi-mem-analysis` can be
used as an equivalent command prefix.

Install the optional gadget-analysis dependencies only if you plan to run
`gadget_detection`:

```bash
python -m pip install -e ".[gadget]"
```

`gadget_detection` invokes the pip-installed `ropper` package through
`python -m ropper`, so it does not depend on a hardcoded `ropper.exe` path.
The optional gadget install uses `ropper`, which currently depends on
`filebytes`; use Python 3.10 through 3.13 for this dependency set. The project
pins `capstone` to the 5.x line so the local analyzers and `ropper` stay on the
same major disassembly version.


## Recommended Workflow

Run `uefi_image_carving` early in an investigation to produce a reusable loaded
image inventory. With `-extract_binaries`, it also writes extracted image
binaries that can be used by `gadget_detection`.

```bash
python -m uefi_dump_analysis uefi_image_carving \
  -f path/to/dump.bin \
  -memory_map path/to/Memory_Map.txt \
  -o artifacts/carved-images/run-name \
  -extract_binaries
```

This first step is recommended, but not mandatory for every plugin.
`gadget_detection` and `image_load_path_detection` can consume carving output
directly. `pointer_hooking_detection` and `inline_hooking_detection` run
directly on the dump and extract the image ranges they need internally.

## Usage

List available modules and show module-specific help:

```bash
python -m uefi_dump_analysis -h
python -m uefi_dump_analysis <module> -h
```

Installed-command equivalent:

```bash
uefi-mem-analysis <module> -h
```

### uefi_image_carving

Extract loaded-image metadata and optionally write image binaries:

```bash
python -m uefi_dump_analysis uefi_image_carving \
  -f path/to/dump.bin \
  -o artifacts/carved-images/run-name \
  -memory_map path/to/Memory_Map.txt \
  -verify path/to/ImageList.txt \
  -extract_binaries
```

The module always writes metadata to `images.csv` and `images.json`.
`-extract_binaries` writes extracted image binaries under `<output>/images`.

Arguments:

- `-f`: required raw dump path.
- `-o`: required output directory for metadata and optional extracted binaries.
- `-memory_map`: recommended `Memory_Map.txt` from the dumper. It is required
  for reliable runtime-address to dump-offset translation during binary
  extraction.
- `-extract_binaries`: optional; writes extracted binaries under
  `<output>/images`.
- `-verify`: optional dumper-produced `ImageList*.txt`. It compares carved
  image records against the dumper's image list and does not change carving
  behavior.
- `-debug`: optional; prints detailed carving diagnostics.

### pointer_hooking_detection

Check EFI service-table pointers for suspicious redirection:

```bash
python -m uefi_dump_analysis pointer_hooking_detection \
  -f path/to/dump.bin \
  -memory_map path/to/Memory_Map.txt \
  -require_valid_crc \
  -o artifacts/reports/pointer_hooks.txt
```

Arguments:

- `-f`: required raw dump path.
- `-memory_map`: recommended for non-identity dumps so pointer targets can be
  classified against the correct loaded-image ranges.
- `-require_valid_crc`: recommended for normal triage; restricts analysis to
  candidate tables whose header CRC32 field is non-zero.
- `-bootservicestable`, `-runtimeservicestable`, `-dxeservicestable`: optional
  table selectors. If none are provided, the module analyzes all three table
  classes.
- `-debug`: optional; prints loaded-image ranges used for classification.
- `-o`: optional report file. Results are always printed to stdout.

### inline_hooking_detection

Check EFI service-table entrypoints for inline or trampoline hooks:

```bash
python -m uefi_dump_analysis inline_hooking_detection \
  -f path/to/dump.bin \
  -memory_map path/to/Memory_Map.txt \
  -require_valid_crc \
  -o artifacts/reports/inline_hooks.txt
```

Arguments:

- `-f`: required raw dump path.
- `-memory_map`: recommended for non-identity dumps because disassembly targets
  are resolved through runtime-address translation.
- `-require_valid_crc`: recommended for normal triage; restricts analysis to
  candidate tables whose header CRC32 field is non-zero.
- `-bootservicestable`, `-runtimeservicestable`, `-dxeservicestable`: optional
  table selectors. If none are provided, the module analyzes all three table
  classes.
- `-debug`: optional; prints loaded-image and executable-range summaries.
- `-o`: optional report file. Results are always printed to stdout.

### gadget_detection

Resolve gadget chains from extracted provider images and candidate values or
candidate images.

From existing carving output:

```bash
python -m uefi_dump_analysis gadget_detection \
  -efi_dir artifacts/carved-images/run-name \
  -candidate_dir artifacts/carved-images/run-name \
  -gadgets_dir artifacts/gadgets/run-name \
  -generate_gadgets \
  -output artifacts/reports/gadget_detection_report.txt
```

Directly from a dump:

```bash
python -m uefi_dump_analysis gadget_detection \
  -dump_file path/to/dump.bin \
  -memory_map path/to/Memory_Map.txt \
  -verify path/to/ImageList.txt \
  -carve_output_dir artifacts/carved-images/run-name \
  -gadgets_dir artifacts/gadgets/run-name \
  -output artifacts/reports/gadget_detection_report.txt
```

When `-dump_file` is used, the module first runs `uefi_image_carving` with
binary extraction enabled. In that mode, `-memory_map` is required for reliable
binary extraction.

Input mode, choose one:

- `-efi_dir`: existing provider-image directory, or a `uefi_image_carving`
  output directory containing an `images/` subdirectory.
- `-dump_file`: raw dump to carve before gadget analysis.

Candidate sources:

- `-candidate_dir`: directory of candidate images to scan, or a
  `uefi_image_carving` output directory. When `-dump_file` is used and no
  candidate source is provided, the auto-carved images are scanned.
- `-candidates`: comma-separated or space-separated candidate values supplied
  directly on the command line.
- `-candidate_file`: file with one candidate value per line.

For existing-image mode (`-efi_dir`), provide at least one candidate source for
the module to analyze.

Common optional arguments:

- `-memory_map`: used only with `-dump_file`; required for reliable binary
  extraction.
- `-verify`: optional dumper-produced `ImageList*.txt` forwarded to the carving
  step for comparison only.
- `-carve_output_dir`: optional output directory for auto-carving when
  `-dump_file` is supplied. Default: `artifacts/carved-images/auto`.
- `-gadgets_dir`: optional directory holding `*.gadgets.txt` files. If omitted
  for carved runs, a run-specific directory under `artifacts/gadgets/` is used.
- `-generate_gadgets`: optional for existing images; generates missing gadget
  caches with `python -m ropper`. It is enabled automatically when
  `-dump_file` is used.
- `-output`: optional report file. Default:
  `artifacts/reports/gadget_detection_report.txt`.
- `-debug`: optional; prints gadget-index and candidate-scan diagnostics.

Advanced optional arguments:

- `-candidate_stride`: byte stride used while scanning candidate images.
  Default: `8`.
- `-image_base`: default runtime base to assume when resolving provider-image
  gadget addresses.
- `-image_base_map`: JSON file mapping image file names to runtime base
  addresses.
- `-min_chain_length`: minimum consecutive gadget count required before a
  sequence is reported as a chain. Default: `4`.
- `-max_gadget_bytes`: maximum byte window re-disassembled for each gadget
  during validation. Default: `32`.
- `-skip_capstone_validation`: skips the local Capstone re-disassembly pass and
  trusts the parsed `ropper` output.
- `-ropper_arch`: architecture string passed to `ropper` when gadget files are
  generated. Default: `x86_64`.
- `-offsets_mode`: interprets candidate values as gadget offsets rather than
  runtime addresses.

### image_load_path_detection

Check for suspicious path-backed image loads.

From existing carving output:

```bash
python -m uefi_dump_analysis image_load_path_detection \
  -carve_dir artifacts/carved-images/run-name \
  -whitelist_file path/to/allowed_paths.txt \
  -output artifacts/reports/image_load_paths.txt
```

Directly from a dump:

```bash
python -m uefi_dump_analysis image_load_path_detection \
  -dump_file path/to/dump.bin \
  -memory_map path/to/Memory_Map.txt \
  -whitelist_file path/to/allowed_paths.txt \
  -output artifacts/reports/image_load_paths.txt
```

The path-loading module only treats exact whitelisted paths as expected. A path
that merely contains `boot` is still reported as suspicious unless it is
explicitly allowed.

Arguments:

- `-carve_dir`: existing `uefi_image_carving` output directory, or a direct
  `images.json` path. Required unless `-dump_file` is used.
- `-dump_file`: raw dump to analyze. Required unless `-carve_dir` is used.
- `-memory_map`: optional `Memory_Map.txt` used when extracting image metadata
  from `-dump_file`.
- `-whitelist_path`: optional exact path to allow. May be repeated or passed as
  a comma-separated list. Matching is exact after path normalization.
- `-whitelist_file`: optional text file containing one exact allowed path per
  line.
- `-output`: optional report file. Default:
  `artifacts/reports/image_load_path_report.txt`.

## Expected Inputs

- `dump.bin`: raw dump generated by the accompanying acquisition tooling.
- `Memory_Map.txt`: runtime-address translation map. It is strongly recommended
  for modules that convert runtime addresses into dump offsets.
- `ImageList*.txt`: optional dumper-generated image list containing loaded-image
  address ranges together with GUID/path identity data. Used by
  `uefi_image_carving -verify` and forwarded by `gadget_detection`; it is not
  required for analysis.

## Outputs

Generated files are written under `artifacts/` by default:

- loaded-image metadata and optional extracted binaries
- gadget cache files generated from analysis images
- text reports produced by the analysis plugins
