# UefiMemAnalysis

`UefiMemAnalysis` is a two-part research toolkit for UEFI memory acquisition and
offline analysis. It accompanies the paper
[UEFI Memory Forensics](https://arxiv.org/pdf/2501.16962) and is organized as:

- `UefiMemDump/`: acquisition component and helper tooling
- `UEFIDumpAnalysis/`: Python-based analysis and detection modules

## Repository Layout

- `UefiMemDump/`
  Acquisition component providing:
  - an EDK II DXE driver intended for integration into firmware images; it writes the dump to removable media during the firmware-to-OS handoff
  - a UEFI shell application that performs the same dump-to-removable-media workflow without requiring firmware integration
  - a helper script, `concat_dump_files.py`, that reassembles split dump chunks into a single dump file
- `UEFIDumpAnalysis/`
  Analysis component with plugins for:
  - UEFI image carving
  - EFI service-table pointer-hook detection
  - inline and trampoline-hook detection
  - suspicious path-based image loading
  - gadget-chain resolution using `ropper`

## Read First

- Acquisition component: [UefiMemDump/README.md](UefiMemDump/README.md)
- Analysis component: [UEFIDumpAnalysis/README.md](UEFIDumpAnalysis/README.md)
- The `UEFIDumpAnalysis` component requires Python 3.10 or later.

Additional acquisition docs:

- EDK II integration and build flow: [UefiMemDump/docs/building-with-edk2.md](UefiMemDump/docs/building-with-edk2.md)
- UEFI shell removable-media workflow: [UefiMemDump/docs/removable-media-shell.md](UefiMemDump/docs/removable-media-shell.md)
- QEMU workflow: [UefiMemDump/docs/qemu-testing.md](UefiMemDump/docs/qemu-testing.md)
- Windows guest VHD preparation: [UefiMemDump/docs/windows-vhd-manual.md](UefiMemDump/docs/windows-vhd-manual.md)

## Quick Setup

If you only want to install the analysis toolkit and inspect its CLI:

```bash
cd UEFIDumpAnalysis
python -m pip install -e .
python -m uefi_dump_analysis -h
```

The repository does not include memory dumps. After acquiring or adding a local
dump and memory map, run the carving pipeline with your local paths:

The `artifacts/` output path is generated locally and intentionally ignored by
Git.

```bash
python -m uefi_dump_analysis uefi_image_carving \
  -f path/to/dump.bin \
  -memory_map path/to/Memory_Map.txt \
  -o artifacts/carved-images/run-name \
  -extract_binaries
```

If you also want the gadget-analysis plugin:

```bash
cd UEFIDumpAnalysis
python -m pip install -e ".[gadget]"
python -m uefi_dump_analysis gadget_detection -h
```

For acquisition, build either `UefiMemDumpApp` or `UefiMemDumpDriver` inside an
external EDK II workspace, collect `Dump/` from removable media, and then
reassemble `dump*.bin` with `UefiMemDump/concat_dump_files.py`.

## Typical Workflow

1. Build either `UefiMemDumpApp` or `UefiMemDumpDriver` inside an upstream EDK II tree.
2. Acquire a dump to removable media on the target platform.
3. Reassemble `dump*.bin` files with `UefiMemDump/concat_dump_files.py`.
4. Analyze the resulting dump with `UEFIDumpAnalysis`.

## Published Source Tree

The published acquisition source tree contains:

- `UefiMemDump/edk2/UefiMemDumpApp/`
- `UefiMemDump/edk2/UefiMemDumpDriver/`

Build those modules against an external EDK II workspace as described in
[UefiMemDump/docs/building-with-edk2.md](UefiMemDump/docs/building-with-edk2.md).

## Status and Support

This repository is being prepared for a public open-source release.

The project is maintained on a best-effort basis by a single maintainer. Bug reports and focused pull requests are welcome, but there is no guaranteed response time or support SLA.
