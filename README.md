# RegSave in C

## Overview

`RegSave in C` is a tool designed to dump sensitive Windows registry hives like `SAM`, `SYSTEM`, and `SECURITY` to text files for analysis. This can be useful in penetration testing engagements, where gaining access to these registry hives might be necessary for further exploitation.

## Features

- Dumps `SAM`, `SYSTEM`, and `SECURITY` hives from the Windows registry.
- Requires elevated privileges (`SeBackupPrivilege` and `SeRestorePrivilege`).
- Bypasses Windows Defender detection due to custom implementation.

## Prerequisites

- **Windows OS** with administrative access.
- C Compiler (e.g., MSVC, GCC for Windows).
- Ability to run the program as **Administrator**.

## Usage

1. Compile the tool using your C compiler (e.g., `cl`, `gcc`):

```sh
cl regsave_in_c.c /link advapi32.lib
```

2. Run the tool from a command prompt with elevated privileges (as Administrator):

```sh
regsave_in_c.exe <output_directory>
```

Example:
```sh
regsave_in_c.exe C:\tools
```

3. The tool will dump the `SAM`, `SYSTEM`, and `SECURITY` hives into the specified output directory:

- sam_dump.txt
- system_dump.txt
- security_dump.txt

## How It Works

The tool first checks whether the current process is running with **high integrity** (Administrator rights). If not, it will print a message and exit. Once verified, it adjusts the necessary privileges (`SeBackupPrivilege` and `SeRestorePrivilege`) to allow access to sensitive parts of the Windows registry.

Next, it opens the required registry hives and saves them to the specified output directory using `RegSaveKey`. The hives dumped are:

- **SAM**
- **SYSTEM**
- **SECURITY**

## Credits

This tool is based on the original concept and C# code provided by Lefteris Panos (GitHub: [leftp](https://github.com/leftp)).

## Disclaimer

This tool is intended for **legal and authorized use only**. The author of this tool is not responsible for any misuse or illegal activity involving the use of this software. Ensure that you have proper authorization before using it in any environment.