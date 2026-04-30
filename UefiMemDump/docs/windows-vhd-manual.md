# Manual: Creating A 10 GB VHD With A 400 MB ESP And Installing Windows For QEMU

This guide creates a 10 GB Virtual Hard Disk (VHD) with a 400 MB EFI System
Partition (ESP), installs Windows from an ISO that contains `install.esd`, and
prepares the disk for QEMU on a Windows host.

It assigns the ESP drive letter `T:` temporarily, verifies it, runs `bcdboot`
immediately, removes `T:`, and then detaches the VHD so the ESP reverts to its
default no-letter state, while `W:` persists for the Windows partition.

## Prerequisites

- Windows 10 or 11 with administrative privileges
- A Windows ISO mounted locally, for example as `E:`
- At least 10 GB of free disk space
- QEMU installed
- OVMF firmware for QEMU
- An elevated Command Prompt

## Notes

- The VHD is dynamically expanding, with a 10 GB maximum by default.
- After the 400 MB ESP and the small reserved partition, roughly 9.5 GB remains for Windows.
- If Windows setup runs out of space, recreate the VHD at 20 GB.
- `T:` is temporary and used for the ESP only while preparing boot files.
- `W:` is the Windows partition.
- The ESP letter is not permanent and must be reassigned each time the VHD is attached.

## Step 1: Create The 10 GB VHD

1. Open **Command Prompt** as Administrator.
2. Launch **DiskPart**:

```text
diskpart
```

3. Create and attach a new VHD:

```text
select vdisk file="D:\WindowsVM.vhd"
detach vdisk
create vdisk file="D:\WindowsVM.vhd" maximum=10240 type=expandable
select vdisk file="D:\WindowsVM.vhd"
attach vdisk
```

Skip the `detach vdisk` line if the file does not already exist.

## Step 2: Partition The VHD With A 400 MB ESP

1. Initialize and convert the disk:

```text
list disk
select disk X
clean
convert gpt
```

Replace `X` with the VHD disk number.

2. Create the ESP and the main Windows partition:

```text
create partition efi size=400
format quick fs=fat32 label="ESP"
create partition primary
format quick fs=ntfs label="Windows"
assign letter=W
```

3. Assign `T:` to the ESP:

```text
list volume
select volume N
detail volume
assign letter=T
```

Replace `N` with the 400 MB FAT32 ESP volume number.

4. Verify the layout:

```text
list partition
list volume
exit
dir T:\
dir W:\
```

If `T:` is missing or inaccessible, reassign it and, if needed, reformat the ESP:

```text
diskpart
select disk X
select partition 2
format quick fs=fat32 label="ESP"
select volume N
assign letter=T
exit
dir T:\
```

5. Detach the VHD for the next stage:

```text
diskpart
select vdisk file="D:\WindowsVM.vhd"
detach vdisk
exit
```

## Step 3: Install Windows Onto The VHD

1. Mount the Windows ISO and confirm `install.esd` exists:

```text
dir E:\sources
```

2. Reattach the VHD and verify drive letters:

```text
diskpart
select vdisk file="D:\WindowsVM.vhd"
attach vdisk
list disk
select disk X
list volume
```

If `T:` is missing, reassign it:

```text
select volume N
assign letter=T
select volume M
assign letter=W
exit
dir T:\
dir W:\
```

3. Apply the Windows image:

```text
dism /Get-WimInfo /WimFile:E:\sources\install.esd
dism /Apply-Image /ImageFile:E:\sources\install.esd /Index:6 /ApplyDir:W:\
dir W:\Windows
```

If space runs out, recreate the VHD at 20 GB:

```text
diskpart
select vdisk file="D:\WindowsVM.vhd"
detach vdisk
create vdisk file="D:\WindowsVM.vhd" maximum=20480 type=expandable
attach vdisk
```

Then repeat the partitioning and apply steps.

4. Configure the bootloader immediately while `T:` is still assigned:

```text
bcdboot W:\Windows /s T: /f UEFI
```

If `bcdboot` fails:

```text
dir W:\Windows
dir T:\
rmdir /S /Q T:\EFI
bcdboot W:\Windows /s T: /f UEFI /v
```

If the ESP needs to be reformatted:

```text
diskpart
select volume N
format quick fs=fat32 label="ESP"
assign letter=T
exit
bcdboot W:\Windows /s T: /f UEFI
```

5. Remove the ESP drive letter immediately after `bcdboot` succeeds:

```text
diskpart
select volume N
remove letter=T
list volume
```

6. Detach the VHD and unmount the ISO:

```text
diskpart
select vdisk file="D:\WindowsVM.vhd"
detach vdisk
exit
```

## Step 4: Verify The VHD

1. Mount the VHD again.
2. Reassign `T:` temporarily to inspect the ESP:

```text
diskpart
select vdisk file="D:\WindowsVM.vhd"
attach vdisk
list volume
select volume N
assign letter=T
exit
```

3. Verify contents:

```text
dir T:\
dir W:\
```

Expected results:

- `T:` contains `EFI\BOOT\BOOTX64.EFI` and Microsoft boot files
- `W:` contains `Windows`, `Program Files`, and related directories

4. Remove `T:` again:

```text
diskpart
select volume N
remove letter=T
exit
```

## Troubleshooting

### ESP Drive Letter Disappears

This is normal. Reassign `T:` when needed:

```text
diskpart
list volume
select volume N
assign letter=T
exit
dir T:\
```

Remove it again afterwards:

```text
diskpart
select volume N
remove letter=T
exit
```

### DISM Errors

- Confirm elevated permissions
- Confirm the correct `install.esd` path and edition index
- Increase the VHD size if space is insufficient

### Bootloader Errors

If `bcdboot` fails:

- verify `W:\Windows` exists
- verify `T:` is FAT32 and writable
- clear `T:\EFI` if needed
- rerun with `/v`

### Boot Issues In QEMU

- Verify `EFI\BOOT\BOOTX64.EFI` exists in the ESP
- Verify the `OVMF.fd` path is correct
- Check the Windows setup logs under `W:\Windows\Panther` if needed
