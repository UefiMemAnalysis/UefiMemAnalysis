# UefiMemDump

`UefiMemDump` is the memory-acquisition component of `UefiMemAnalysis`. It
captures UEFI memory dumps and related artifacts for later analysis by
`UEFIDumpAnalysis`.

The acquisition component includes:

- `edk2/UefiMemDumpApp/`: UEFI shell application
- `edk2/UefiMemDumpDriver/`: DXE driver
- `concat_dump_files.py`: utility for reassembling split `dump*.bin` chunks
  into a single dump file

## What Each Variant Does

- `UefiMemDumpApp`
  A UEFI shell application for manual acquisition from removable media. It
  writes its output back to the same removable-media filesystem that loaded the
  application.
- `UefiMemDumpDriver`
  A DXE driver intended for integration into firmware images. It performs
  acquisition during the firmware-to-OS handoff and writes the dump to
  removable media. See the [QEMU workflow](docs/qemu-testing.md) for the
  recommended guest setup.

Both variants emit:

- `\Dump\dump*.bin`
- `\Dump\Memory_Map.txt`
- `\Dump\ImageList.txt`

## Acquisition Workflow

Use this workflow if you already have an EDK II workspace:

1. Add either `UefiMemDumpApp` or `UefiMemDumpDriver` from `UefiMemDump/edk2/` to your workspace package tree.
2. Reference the chosen module `.inf` from the target platform `.dsc` and `.fdf`.
3. Build the platform in EDK II.
4. Run `UefiMemDumpApp.efi` from removable media, or boot a firmware image that includes `UefiMemDumpDriver`.
5. Copy the resulting `Dump/` directory from the removable media and reconstruct the full dump with `python concat_dump_files.py <input_dir> <output_file>`.
6. Analyze the reconstructed dump with the commands documented in the [analysis guide](../UEFIDumpAnalysis/README.md).

## Build and Usage Documentation

- [EDK II setup and integration](docs/building-with-edk2.md)
- [Running the shell app from removable media](docs/removable-media-shell.md)
- [Testing with QEMU and OVMF](docs/qemu-testing.md)
- [Preparing a Windows guest VHD for QEMU driver testing](docs/windows-vhd-manual.md)

## Concatenating Dump Chunks

An acquisition run can produce multiple sequential `dump*.bin` chunks.
Reassemble the chunks into a single dump file before analysis:

```bash
python concat_dump_files.py <input_dir> <output_file>
```

Example, where `path/to/dump-chunks` contains the collected `dump*.bin` files:

```bash
python concat_dump_files.py path/to/dump-chunks FullUefiDump.bin
```

The script sorts `dump*.bin` files numerically and reconstructs the full dump in
order.
Run `python concat_dump_files.py -h` for the full CLI help text.
