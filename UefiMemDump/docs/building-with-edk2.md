# Building UefiMemDump With EDK II

`UefiMemDumpApp` and `UefiMemDumpDriver` are EDK II modules and are built
inside an upstream EDK II workspace.

Official upstream references:

- EDK II repository: <https://github.com/tianocore/edk2>
- TianoCore build setup guide: <https://github.com/tianocore/tianocore.github.io/wiki/Getting-Started-with-EDK-II>

## Basic Setup

1. Clone upstream EDK II and initialize submodules.
2. Follow the upstream EDK II setup guide for the Python requirements and environment initialization used by your selected tree and toolchain.
3. Copy `UefiMemDumpApp` and `UefiMemDumpDriver` into the EDK II workspace, for example under `UefiMemDump/`.
4. Add the module `.inf` paths to the target platform `.dsc` and `.fdf` files.
5. Build the platform image.

## Add The Modules To OVMF

If you are building with OVMF, add these module paths to the relevant platform
files, typically `OvmfPkg/OvmfPkgX64.dsc` and `OvmfPkg/OvmfPkgX64.fdf` or the
equivalent files for your target platform. The exact paths depend on where you
place the modules in your workspace. If you keep them under `UefiMemDump/`, the
references are:

```text
UefiMemDump/UefiMemDumpApp/UefiMemDump.inf
UefiMemDump/UefiMemDumpDriver/UefiMemDump.inf
```

At minimum:

- add the `.inf` to the platform `.dsc` so EDK II knows about the module
- add the `.inf` to the platform `.fdf` if you want it placed into the firmware image

For the DXE driver, the `.fdf` entry is the usual way to include it in the boot
firmware image. For the shell application, the build can still be driven from
the platform, but the final `.efi` is commonly copied onto removable media and
launched from the shell.
