# UefiMemDump

`UefiMemDump` is the memory-acquisition component of `UefiMemAnalysis`. It
captures UEFI memory dumps and related artifacts for later analysis by
`UEFIDumpAnalysis`.

It contains three public pieces:

- `edk2/UefiMemDumpApp/`: UEFI shell application
- `edk2/UefiMemDumpDriver/`: DXE driver
- `concat_dump_files.py`: host-side helper for reassembling split `dump*.bin` chunks into a single dump file

## What Each Variant Does

- `UefiMemDumpApp`
  A UEFI shell application for manual acquisition from removable media. It
  writes its output back to the same removable-media filesystem that loaded the
  application.
- `UefiMemDumpDriver`
  A DXE driver intended for integration into firmware images. It performs
  acquisition during the firmware-to-OS handoff and writes the dump to
  removable media. See the QEMU workflow documentation for the recommended
  guest setup.

Both variants emit:

- `\Dump\dump*.bin`
- `\Dump\Memory_Map.txt`
- `\Dump\ImageList.txt`

## Published Source Tree

The published acquisition source tree contains only:

- `UefiMemDump/edk2/UefiMemDumpApp/`
- `UefiMemDump/edk2/UefiMemDumpDriver/`

Build those modules inside an external EDK II workspace and add their `.inf`
files to the appropriate platform `.dsc` and `.fdf` files.

## Quick Setup

Use this path if you already have an EDK II workspace:

1. Add either `UefiMemDumpApp` or `UefiMemDumpDriver` from `UefiMemDump/edk2/` to your workspace package tree.
2. Reference the chosen module `.inf` from the target platform `.dsc` and `.fdf`.
3. Build the platform in EDK II.
4. Run `UefiMemDumpApp.efi` from removable media, or boot a firmware image that includes `UefiMemDumpDriver`.
5. Copy the resulting `Dump/` directory from the removable media and reconstruct the full dump with `python concat_dump_files.py <input_dir> <output_file>`.
6. Analyze the reconstructed dump with the commands documented in [../UEFIDumpAnalysis/README.md](../UEFIDumpAnalysis/README.md).

## Build And Usage Docs

- EDK II setup and integration: [docs/building-with-edk2.md](docs/building-with-edk2.md)
- Running the shell app from removable media: [docs/removable-media-shell.md](docs/removable-media-shell.md)
- Testing with QEMU and OVMF: [docs/qemu-testing.md](docs/qemu-testing.md)
- Preparing a Windows guest VHD for QEMU driver testing: [docs/windows-vhd-manual.md](docs/windows-vhd-manual.md)

## Concatenating Dump Chunks

The acquisition code writes multiple sequential `dump*.bin` files. Join them on
the host with:

```bash
python concat_dump_files.py <input_dir> <output_file>
```

Example:

```bash
python concat_dump_files.py E:\Dump FullUefiDump.bin
```

The script sorts `dump*.bin` files numerically and reconstructs the full dump in order.
Run `python concat_dump_files.py -h` for the full CLI help text.
