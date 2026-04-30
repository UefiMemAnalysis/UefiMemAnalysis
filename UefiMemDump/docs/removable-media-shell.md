# Running UefiMemDumpApp From Removable Media

This flow is intended for the UEFI shell application,
`UefiMemDumpApp/UefiMemDump.inf`.

## Requirements

- A built `UefiMemDumpApp` `.efi` binary
- A removable-media device with enough free space to hold:
  - the UEFI shell files
  - the dump application
  - the generated dump output

Useful upstream downloads:

- Rufus: <https://rufus.ie/en/>
- UEFI Shell releases: <https://github.com/pbatard/UEFI-Shell/releases>
- UEFI Shell project: <https://github.com/pbatard/UEFI-Shell>

## Important Filesystem Note

Because this workflow executes in the pre-boot environment, the removable-media
filesystem should be formatted with `FAT32`, not `NTFS`, even if Rufus suggests `NTFS` by
default.

## Prepare The Removable-Media Device

1. Open Rufus and select the target removable-media device.
2. If the device does not appear in Rufus, press `Alt`+`F` and check again.
3. Choose the downloaded UEFI Shell ISO as the boot selection.
4. Set the filesystem to `FAT32`.
5. Create the media.

## Copy The Dump Application

After Rufus finishes:

1. Mount or open the removable-media filesystem.
2. Copy the built `UefiMemDumpApp` binary onto the removable-media device.
3. Keep the device attached to the target system.

The application writes its output to the same filesystem device that loaded it,
so the selected removable-media device must have enough free capacity for the
resulting memory dump.

## Run The Application

1. Boot the target system from the prepared UEFI shell media.
2. At the shell prompt, refresh mappings if needed:

```text
map -r
```

3. Switch to the filesystem that contains the application, for example:

```text
fs0:
```

4. Run the application:

```text
UefiMemDump.efi
```

## Expected Output

The application writes:

- `\Dump\dump*.bin`
- `\Dump\Memory_Map.txt`
- `\Dump\ImageList.txt`

After collecting the files on a host system, concatenate the split dump chunks:

```bash
python concat_dump_files.py <path-to-Dump> FullUefiDump.bin
```
