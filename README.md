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
 [+] find CRC32_CRC32_m_tab_le at 4b2992d0
 [+] find SHA256_SHA256_K at 4b28d9e0
[*] processing sparse consts
 [+] find SHA256_SHA256_H at 4b2edb20
 [+] find MD5_MD5_initstate at 4b37a610
[*] processing operand consts
findcrypt.py> Finished!
```

## Known issues

 - can't find consts in 64bit binary