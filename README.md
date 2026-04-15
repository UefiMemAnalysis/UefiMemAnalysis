# UefiMemAnalysis
A memory forensics framework for detecting UEFI-level threats during the pre-boot phase. Consists of **UEFIMemDump**, a memory acquisition tool implemented as a DXE driver and UEFI shell application, and **UEFIDumpAnalysis**, an extensible collection of analysis modules for detecting function pointer hooking, inline hooking, malicious image loading, and gadget-based control-flow patterns in UEFI memory dumps. Evaluated against real-world bootkits including ThunderStrike, CosmicStrand, and Glupteba. Vendor-agnostic and compatible with any UEFI-compliant platform.
This project is a proof-of-concept implementation that validates the research findings detailed in the academic paper: [UEFI Memory Forensics](https://arxiv.org/pdf/2501.16962).

## Project Goals

This project aims to provide researchers and practitioners with an open-source solution to investigate firmware-level threats, develop additional analysis modules, and advance overall below-OS security through UEFI memory analysis. The framework's architecture is designed to be extendable, allowing for the creation of new plugins to adapt to emerging threats and research needs.

## Project Overview

Modern computing systems rely on the Unified Extensible Firmware Interface (UEFI). However, UEFI is increasingly targeted by threat actors. This project addresses the lack of below-OS memory forensics by providing a framework for UEFI memory analysis.

This framework consists of two primary components:

* **UefiMemDump:** A memory acquisition tool implemented as both a DXE driver and a UEFI shell application.
* **UEFIDumpAnalysis:** An extendable collection of Python-based analysis modules.

## Features

### UefiMemDump (C)

UefiMemDump captures complete system memory snapshots during the UEFI boot process before OS initialization. It is implemented in two ways:

* **DXE Driver:**
    * Captures memory in a virtualized environment.
    * Tested in a QEMU environment with EDK II firmware and Windows 11.
    * Writes memory snapshots to the virtual hard disk (VHD).
* **UEFI Shell Application:**
    * Captures memory in physical systems.
    * Tested on System76 Adder WS and Lenovo ThinkPad T14 Gen4 laptops.
    * Writes memory snapshots to an external USB device.

**Build Instructions:**

* **DXE Driver:**
    * Add the driver's INF path to the `.dsc` and `.fdf` files of the target BIOS.
    * Compile and run the BIOS code using the EDK2 framework ([https://github.com/tianocore/edk2](https://github.com/tianocore/edk2)).
    * In a virtualized environment, ensure a Windows operating system is loaded to allow dump files to be written to its file system.
* **UEFI Shell Application:**
    * Load the application from a peripheral device during the UEFI boot phase.

**Note:** The dumping process creates multiple sequential files due to FAT file system limitations. Use `ConcatFiles.c` (instructions below) to concatenate them into a single binary memory dump file.

########### TODO - add instruction and run commands ###############

### UEFIDumpAnalysis (Python)

UEFIDumpAnalysis provides a suite of Python-based analysis modules:

* **Function Pointer Hooking Detection:**
    * Analyzes EFI Boot, Runtime, and DXE Services Tables.
    * Identifies unauthorized modifications to service table function pointers.
    * Outputs metadata including GUID, driver memory region, and file path.
* **Inline Hooking Detection:**
    * Disassembles service function code using Capstone.
    * Detects `jmp` and `call` instructions that redirect execution flow.
    * Outputs metadata including function name, hook address, target address, and GUID/file path.
* **UEFI Image Carving:**
    * Extracts PE/COFF files from memory dumps.
    * Uses `b'ldri'` structures to identify valid PE files.
    * Saves extracted files to a specified output directory, named by GUID or file path.

**Python Dependencies:**
capstone==5.0.3

**Installation:**

1.  Clone the repository: `git clone https://github.com/uefimemdump/UefiMemDump`
2.  Navigate to the project directory.
3.  Install the required Python dependencies: `pip install -r requirements.txt`

**Running the Python Modules:**

1.  Navigate to the `UEFIDumpAnalysis` directory.
2.  Run the main script `UEFIMemAnalysis.py` with the desired module and arguments.

```bash
python UEFIMemAnalysis.py <module_name> <arguments>
```
## Available Modules:

### Analyze Services (Function Pointer Hooking Detection)

This module analyzes EFI Boot, Runtime, and DXE Services Tables from a memory dump to detect function pointer hooking.

**Usage:**
```bash
python UEFIMemAnalysis.py AnalyzeServices -f <dump_file> [-bootservicestable] [-runtimeservicestable] [-dxeservicestable] [-o <output_file>]
```
### Inline Hook Detection
This module analyzes EFI Boot, Runtime, and DXE Services Tables from a memory dump to detect inline hooking.

**Usage:**
```bash
python UEFIMemAnalysis.py "Inline Hook Detection" -f <dump_file> -o <output_file> [-bootservicestable] [-runtimeservicestable] [-dxeservicestable]
```

### Image Extraction (UEFI Image Carving)
This module extracts and saves UEFI images from a memory dump to an output directory.

**Usage:**
```bash
python UEFIMemAnalysis.py "Image Extraction" -f <dump_file> -o <output_directory>
```

### ConcatFiles.c Instructions (TBD):

Instructions for building and running the ConcatFiles.c application will be added here.

## Directory Structure
```bash
UefiMemDump/
├── UEFI Application and Driver/
│   ├── Application/
│   │   ├── *.c
│   │   ├── *.h
│   │   ├── *.inf
│   │   └── *.efi
│   └── Driver/
│       ├── *.c
│       ├── *.h
│       ├── *.inf
│       └── *.efi
├── UEFIDumpAnalysis/
│   ├── modules/
│   │   ├── InlineHookingDetection.py
│   │   ├── PointerHookingDetection.py
│   │   └── UEFIImageCarving.py
│   ├── UEFIMemAnalysis.py
│   └── requirements.txt
├── ConcatFiles.c
└── README.md
```

## License
This project is licensed under the MIT License.

## Academic Paper
For more details, refer to the academic paper: https://arxiv.org/pdf/2501.16962

## Contact Information
Hadar Cochavi Gorelik: <hadarcoc@post.bgu.ac.il>

Kalanit Suzan Segal: <kalanits@post.bgu.ac.il>

Oleg Brodt: <bolegb@bgu.ac.il>

