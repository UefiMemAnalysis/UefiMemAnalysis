# QEMU Testing

This document covers the QEMU workflow for implementation and testing of
`UefiMemDump`, especially the DXE driver path.

## Key Driver Behavior

`UefiMemDumpDriver` is designed to dump memory near `ExitBootServices`. To
simulate a real system as closely as possible, the recommended QEMU setup boots
an actual guest OS from a virtual disk.

Testing the driver on a plain firmware-only boot is not representative and can
fail to exercise the intended path, because the dump is tied to the
pre-`ExitBootServices` event. In practice, booting a Windows guest is the
recommended test setup.

For preparing that Windows guest disk, see:

- [windows-vhd-manual.md](windows-vhd-manual.md)

## Create A Virtual Removable-Media Image

If you want the guest to dump to removable media in QEMU, create a removable-
media image. A 4 GB image is usually enough for a 1 GB guest memory
configuration, but size it according to the memory you configured in QEMU.

The example below was used on Ubuntu. Equivalent tools can be used on other
Unix-like hosts.

```bash
dd if=/dev/zero of=usb_dump.img bs=1M count=4096
mkfs.fat -F 32 usb_dump.img
```

## QEMU USB Additions

Add these options to attach the virtual USB image:

```text
-drive if=none,id=usbstick,file=<path-to-usb_dump.img>,format=raw
-device qemu-xhci,id=xhci
-device usb-storage,bus=xhci.0,drive=usbstick,bootindex=-1
```

## Example QEMU Command

The following is the command structure used during development. Replace the
paths with values from your local environment.

```powershell
qemu-system-x86_64 ^
 -cpu qemu64,+rdrand ^
 -fw_cfg name=opt/org.tianocore/X-Cpuhp-Bugcheck-Override,string=yes ^
 -m 1G ^
 -drive if=pflash,format=raw,readonly=on,file=<path-to-OVMF_CODE.fd> ^
 -drive if=pflash,format=raw,file=<path-to-OVMF_VARS.fd> ^
 -drive file=<path-to-Windows.vhd>,format=vpc ^
 -drive if=none,id=usbstick,file=<path-to-usb_dump.img>,format=raw ^
 -device qemu-xhci,id=xhci ^
 -device usb-storage,bus=xhci.0,drive=usbstick,bootindex=-1 ^
 -netdev user,id=net0,net=10.0.2.0/24,dhcpstart=10.0.2.15 ^
 -device virtio-net-pci,netdev=net0 ^
 -vga std ^
 -debugcon file:<path-to-debug.log> ^
 -global isa-debugcon.iobase=0x402 ^
 -monitor stdio
```

## Notes

- `OVMF_CODE.fd` and `OVMF_VARS.fd` come from your EDK II build output.
- The Windows guest disk is important for realistic driver testing.
- The removable-media image should be FAT32.
- `debug.log` is useful for instrumented runs and troubleshooting.

## Related Docs

- EDK II build flow: [building-with-edk2.md](building-with-edk2.md)
- Windows guest preparation: [windows-vhd-manual.md](windows-vhd-manual.md)
