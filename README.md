# UefiMemAnalysis

`UefiMemAnalysis` is an open-source framework for UEFI memory acquisition and
offline analysis of UEFI memory dumps. It accompanies the paper
[UEFI Memory Forensics](https://ieeexplore.ieee.org/document/11624234/), which has been
accepted to the 11th IEEE European Symposium on Security and Privacy
(Euro S&P).

The repository includes acquisition tooling for collecting UEFI memory dumps and
an analysis toolkit for investigating UEFI memory artifacts and detecting
suspicious runtime behavior.

## Repository Layout

- `UefiMemDump/`
  Acquisition component providing:
  - an EDK II DXE driver intended for integration into firmware images; it writes the dump to removable media during the firmware-to-OS handoff
  - a UEFI shell application that performs the same dump-to-removable-media workflow without requiring firmware integration
  - a utility, `concat_dump_files.py`, that reassembles split dump chunks into a single dump file
- `UEFIDumpAnalysis/`
  Analysis component with plugins for:
  - UEFI image carving
  - EFI service-table pointer-hook detection
  - inline and trampoline-hook detection
  - suspicious path-based image loading
  - gadget-chain resolution using `ropper`

## Read First

- [Acquisition guide](UefiMemDump/README.md)
- [Analysis guide](UEFIDumpAnalysis/README.md)
- The `UEFIDumpAnalysis` component requires Python 3.10 through 3.13.

Additional acquisition docs:

- [EDK II integration and build flow](UefiMemDump/docs/building-with-edk2.md)
- [UEFI shell removable-media workflow](UefiMemDump/docs/removable-media-shell.md)
- [QEMU workflow](UefiMemDump/docs/qemu-testing.md)
- [Windows guest VHD preparation](UefiMemDump/docs/windows-vhd-manual.md)

## Quick Setup

Clone the repository, install the Python analysis package, and confirm that the
CLI is available:

```bash
git clone https://github.com/UefiMemAnalysis/UefiMemAnalysis.git
cd UefiMemAnalysis
python -m pip install -e ./UEFIDumpAnalysis
python -m uefi_dump_analysis -h
```

To include the optional gadget-analysis dependencies:

```bash
python -m pip install -e "./UEFIDumpAnalysis[gadget]"
python -m uefi_dump_analysis gadget_detection -h
```

## Typical Workflow

1. Build either `UefiMemDumpApp` or `UefiMemDumpDriver` inside an upstream EDK II tree.
2. Acquire a dump to removable media on the target platform.
3. Reassemble `dump*.bin` files with `UefiMemDump/concat_dump_files.py`.
4. Analyze the resulting dump with `UEFIDumpAnalysis`.

## Status and Support

This project is maintained on a best-effort basis. Please report reproducible
bugs through [GitHub Issues](https://github.com/UefiMemAnalysis/UefiMemAnalysis/issues)
and include the affected component, platform, commands, logs or traceback, and
enough context to reproduce the problem. There is no guaranteed response time or
support SLA.

## Citation and Contributions

If you use this project or the accompanying framework in academic or research
work, please cite the paper below. The BibTeX entry currently cites the arXiv
preprint; an updated venue citation will be provided when available.

```bibtex
@INPROCEEDINGS{11624234,
  author={Segal, Kalanit Suzan and Cochavi Gorelik, Hadar and Brodt, Oleg and Elbahar, Yuval and Elovici, Yuval and Shabtai, Asaf},
  booktitle={2026 IEEE 11th European Symposium on Security and Privacy (EuroS&P)}, 
  title={UEFI Memory Forensics: A Framework for UEFI Threat Analysis}, 
  year={2026},
  volume={},
  number={},
  pages={208-224},
  keywords={Booting;Memory;Microprogramming;Modules (abstract algebra);Forensics;Manuals;Runtime;Signal detection;Security;Loading;UEFI security;Memory forensics;Memory acquisition;Bootkits;Firmware analysis;Malware detection},
  doi={10.1109/EuroSP68448.2026.00024}}

```

Pull requests that fix bugs, improve documentation, or add focused enhancements
are welcome. For larger feature proposals, please open an issue before
implementation.
