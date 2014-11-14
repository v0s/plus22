+22: x64 binary → x86 Hex-Rays
==============================

Plus22 transforms x86_64 executables to be processed with 32-bit version of Hex-Rays Decompiler.

This tool was created in mid-2013 for internal use in More Smoked Leet Chicken, and made public 
in November 2014 when Hex-Rays x64 finally came out.


Usage
-----

```
php plus22.php [-va] {x64_binary.bin or listing.asm}

  If file name ends with '.asm', it will be interpreted as an ASM listing.
  Otherwise, it will be interpreted as x64 ELF/PE, and disassembled with IDA.

  -v    be verbose and leave all temporary files
  -a    AutoNop all lines with errors
```

You can use _misc\php.exe to run the script.

Plus22 is designed to run in Windows environment, and works well under Wine.


Specifying your IDA path
------------------------

To decompile and restore types automatically, Plus22 needs to know where IDA is installed.
You can add your path to $idaPaths array right at the top of script, or have it done for you 
automatically when Plus22 needs your IDA installation path.

Without specifying IDA path, you can do the following by hand:

1. Load binary in IDA64
2. View → Unhide all (uncollapse functions)
3. File → Produce file → Create ASM file
4. `php plus22.php mega_binary.asm`
5. If you're lucky, .obj is created.
6. Load .obj in IDA
7. File → Script file...  — execute mega_binary+22.idc for correct function types


Files
-----

* `_misc\php.exe` — compatible PHP version from http://windows.php.net/
* `_misc\original_instructions.idc` — IDA script to manually load original instruction toggler
* `_misc\functype.db` — imported functions type database, parsed from IDA TIL collection
* `_misc\jwasm.exe` — fast Masm-like assembler from http://sourceforge.net/projects/jwasm/
* `_misc\exporter.idc` — ASM listing export helper IDA script
* `_example\` — Network 300 from ebCTF 2013 Teaser processed with Plus22. This x64 binary uses raw socket API and heavily utilizes BN_* functions from OpenSSL.


Changelog
---------

v0.3
* [+] error correction mode: allows to fix ASM source interactively and re-compile right in +22
* [+] '-a' command line switch: auto-nop all errors without user interaction

v0.2.3
* [+] type matching for float calling convention (XMM registers)
* [+] type guessing support for XMM
* [+] automatic 64-bit -> 32-bit constant truncation

v0.2.2
* [-] removed collapsed function handling
* [+] press Alt-Z to toggle between converted and original x64 instructions

v0.2.1
* [+] changeable calling convention: now supports windows x64 binaries
* [+] automatic main() detection
* [.] more compatible data types
* [.] variadic arguments expansion

v0.2
* [+] type matching for imports
* [+] type guessing for internal functions
* [+] fully automatic ELF disassembly

v0.1.1
* [+] clip_type_helper: automatic calling convention converter
* [.] more automatic patches

v0.1
* [+] directive and instruction patches
* [+] being able to build an x86 binary
* [.] collapsed function emulation

