# py-findcrypt-ghidra

FindCrypt for Ghidra written in Python.
All constants are referenced from [findcrypt](https://github.com/you0708/ida/tree/master/idapython_tools/findcrypt).

## Installation

clone this repository and add the cloned path to `Script Directories` in `Script Manager` of Ghidra.

## Usage

Run `findcrypt.py` after installation. once successfully done, this script will show the found algorithm name and address, like following.

```bash
findcrypt.py> Running...
[*] processing non-sparse consts
 [+] find CRC32_m_tab_le for CRC32 at 4b2992d0
 [+] find SHA256_K for SHA256 at 4b28d9e0
[*] processing sparse consts
 [+] find SHA256_H for SHA256 at 4b2edb20
 [+] find MD5_initstate for MD5 at 4b37a610
[*] processing operand consts
findcrypt.py> Finished!
```

## Known issues

 - can't find consts in 64bit binary
 - maybe doesn't work for sparse consts in non-function