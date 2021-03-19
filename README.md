# CLRvoyance

CLRvoyance is a shellcode kit that supports bootstrapping managed assemblies into unmanaged (or managed) processes. It provides three different implementations of position independent shellcode for CLR hosting, as well as a generator script for quickly embedding a managed assembly in position independent shellcode.

Please see the release blogpost [here](https://www.accenture.com/us-en/blogs/cyber-defense/clrvoyance-loading-managed-code-into-unmanaged-processes) for technical information.

# Usage

```
$ py clrvoyance.py -h
usage: clrvoyance.py [-h] -a [executable] [-p [32|64]] [-d [net|c]] [-n] [--apc]

optional arguments:
  -h, --help       show this help message and exit
  -a [executable]  Assembly
  -p [32|64]       Platform
  -d [net|c]       Dump binary shellcode of assembly
  -n               Load assembly into a new domain
  --apc            Use safe APC shellcode
```

CLRvoyance requires Python 3.6+ to generate embedded payloads. Using our included ExampleAssembly, we can generate 32-bit raw shellcode using the following:

```
$ py clrvoyance.py -a ExampleAssembly.exe -p 32
[+] 4608 byte assembly
[+] 1381 byte bootstrap
[+] 5988 byte shellcode written out (c:\users\bja\Desktop\project\clrvoyance\ExampleAssembly\ExampleAssembly\bin\Debug\ExampleAssembly.exe.shellcode)
```

`ExampleAssembly.exe.shellcode` can then be used as your shellcode payload.

If we want to view the shellcode for programmatic consumption, the `-d` flag can be used:

```
$ py clrvoyance.py -a ExampleAssembly.exe.shellcode -p 32 -d net
byte[] shellcode={
0xe8,0x00,0x00,0x00,0x00,0x5b,0x68,0x42,0x31,0x0e,0x00,0x68,0x88,0x4e,0x0d,0x00,
0xe8,0x23,0x04,0x00,0x00,0x6a,0x04,0x68,0x00,0x10,0x00,0x00,0x68,0x00,0x03,0x00,
0x00,0x6a,0x00,0xff,0xd0,0x85,0xc0,0x0f,0x84,0x46,0x03,0x00,0x00,0x64,0x8b,0x35,
0x18,0x00,0x00,0x00,0x89,0x46,0x14,0x68,0x86,0x57,0x0d,0x00,0x68,0x88,0x4e,0x0d,
0x00,0xe8,0xf2,0x03,0x00,0x00,0x64,0x8b,0x35,0x14,0x00,0x00,0x00,0x83,0xc6,0x38,
...snip...
```

The provided assemblies were compiled using nasm 2.14. If you modify the shellcode, please ensure you update offsets in `clrvoyance.py`. 

# Code 

The project is broken up into multiple files described below:

```
clrvoyance.py  	    - Generator script
sc-*-clr.asm 	    - Primary CLR loader; RX page support
sc-*-clr-apc.asm    - APC CLR loader
sc-*-clr-rwx.asm    - RWX version of CLR loader
sc-*-clrnd.asm      - CLR loader with new domain
sc-*-clrnd-apc.asm  - APC CLR loader with new domain
sc-*-api-functions  - Helper functions
sc-32-jscript.asm   - Executes JScript instead of an assembly
sc-64-macros.asm    - 64-bit helper macros
```