---
title: "DarkCloud Sample Using a Multistage Loader to Deliver an Infostealer"
author: ngname
date: 2025-12-04 21:45 +0700
categories: [Reverse Engineering]
tags: [windows, malware analysis, darkcloud]
comments: true
pin: true
---

- Size: 1,31 MB
- MD5 hash: 1267884aa681e9a3a5416ac2c2a67107
- 32bit executable
- Name: P Order © - PO232825.exe

Loading the executable into DiE, we can see it detected `Format: AutoIt (3.XX)`

![IMAGE](/assets/img/Darkloader_sample/DiE.PNG)

> AutoIt is *a freeware BASIC-like scripting language* designed for automating the Windows GUI and general purpose scripting.

According to the [official autoit website](https://www.autoitscript.com/site/autoit/) it can also be used for manipulate windows, controls and processes and compiled into standalone executables

## The AutoIt executable

I looked around in `Resource Hacker` and found that inside the `RCData` resource there is a compiled AutoIt script file indicated by the header `AU3!`

![IMAGE](/assets/img/Darkloader_sample/au3.PNG)

When using [Aut2Exe](https://www.autoitscript.com/autoit3/docs/intro/compiler.htm) - AutoIt's compiler, it creates an interpreter (the `.exe` file) and the AutoIt bytecode (`.a3x` file) often stored as a resource inside the executable

So basically the embedded resource in `RCData` (`.a3x` file) contains the actual malicious code

## The AutoIt script

We can use [Exe2Aut](https://github.com/JacobPimental/exe2aut/blob/master/exe2aut.exe) to decompile into an obfuscated AutoIt source code, these are the main functions

![IMAGE](/assets/img/Darkloader_sample/1.PNG)

- `YBRGDMEN` is used for string XOR decryption using `40` as a hardcoded key

- `QDWJDUPM` is just another implementation of `StringLen`

- `YJCNNGCI` is a `SubString` implementation but it is only declared here and never got called in the script

Below is the deobfuscated code

![IMAGE](/assets/img/Darkloader_sample/2.PNG)

- The script first uses `FileInstall` to extract an embedded resource named `Glagolitic` from within the AutoIt executable and writes it to `%TEMP%`, overwriting any existing file with the same name. It then assigns the built-in AutoIt function `DllCall` to the variable **`FNHQKAWG`** using `Execute()`. After that, the script initializes **`TBEBOFTO`** with a large hexadecimal string (the `0x` prefix means that the string is in hexadecimal format)

> **Glagolitic** is the XORed Darkcloud stealer binary, and **TBEBOFTO** is actually an encrypted shellcode that is later used to decrypts Glagolitic and injects it into another process

![IMAGE](/assets/img/Darkloader_sample/3.PNG)

Finally it decrypts `TBEBOFTO` and then use `DllCall` to execute 2 more DLL functions, we can reuse the decryption code above to decrypt the XORed strings

![IMAGE](/assets/img/Darkloader_sample/4.PNG)

![IMAGE](/assets/img/Darkloader_sample/5.PNG)

The script used `DllStructCreate` and `DllStructSetData` to create a buffer that stores the decrypted shellcode (Which is inside the running AutoIt executable), gets a pointer to the shellcode's base address, uses `VirtualProtect` to set the memory region permission to `PAGE_EXECUTE`

Finally it executes shellcode from the 9200th byte using `CallWindowProc` 

## The Shellcode loader

To extract the shellcode we can simply just modify some of the code in the original script to write the decrypted result into a file instead of executing

![IMAGE](/assets/img/Darkloader_sample/6.PNG)

Because the result of the decryption is in string format, we can delete `0x` prefix and then hex decode to get the actual shellcode

I used [sclauncher](https://github.com/jstrosch/sclauncher) to turns the shellcode into a 32bit executable, set entrypoint at the 9200th byte for easier debugging and static analysis

`sclauncher.exe -f="shellcode.bin" -ep=9200 -pe -32 -o="PE.exe"`

### Hashing algorithm

A custom CRC32 hashing function is used for resolving APIs

![IMAGE](/assets/img/Darkloader_sample/11.PNG)

### Resolve APIs dynamically

- Firstly prepares several module names: `kernel32.dll`, `ntdll.dll`, `user32.dll`, `advapi32.dll`, `shlwapi.dll`, `shell32.dll`

![IMAGE](/assets/img/Darkloader_sample/7.PNG)

Then it builds a huge look up table for the API hashes, the odd indexes are the hashes and the even indexes are pointers to where the resolved function pointers will be stored 

![IMAGE](/assets/img/Darkloader_sample/8.PNG)

![IMAGE](/assets/img/Darkloader_sample/10.PNG)

- After that it gets the base address of the module

- Resolve the APIs from given hashes by going through the exported function names of module, computes their CRC32 hash and if it matches the given value, returns the API address and stores it into even indexes above

  ​	![IMAGE](/assets/img/Darkloader_sample/9.PNG)

- The process is then reapeated for other modules

### Anti VM/Debugger

- This function performs a timing-based anti-debug check. It check the time before and after a 500 ms sleep, if the delay is shorter than 500ms it terminates the process

![IMAGE](/assets/img/Darkloader_sample/12.PNG)

If passed, the shellcode then checks for the file `Glagolitic` in `%TEMP%` then allocates memory to store it, the protection flag is set to 4 (Only read and write permission)

![IMAGE](/assets/img/Darkloader_sample/13.PNG)

### Switching execution

Firstly initalizes some strings: `.exe`, `underbalance`, `Myriopoda`

- Check if `C:\\Users\\AppData\\Local\\underbalance` exists, if not, create that folder

![IMAGE](/assets/img/Darkloader_sample/14.PNG)

![IMAGE](/assets/img/Darkloader_sample/15.PNG)

- Check if `C:\\Users\\AppData\\Local\\underbalance\\Myriopoda.exe` exists, if not, create that file and then copy the current process to that file

> The initial AutoIt executable will be copied into `Myriopoda.exe`

![IMAGE](/assets/img/Darkloader_sample/16.PNG)

![IMAGE](/assets/img/Darkloader_sample/17.PNG)

- Finally calls `CreateProcessW` to run `Myriopoda.exe` as a new process and exit the current process

![IMAGE](/assets/img/Darkloader_sample/18.PNG)

### Persistence

- Check for `C:\Users\nam\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Myriopoda.vbs`

![IMAGE](/assets/img/Darkloader_sample/19.PNG)

If `Myriopoda.vbs` doesnt exist it will create one in `Startup\`

```vbscript
Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "C:\Users\admin\AppData\Local\underbalance\Myriopoda.exe", 1
Set WshShell = Nothing
```

> This will make sure the malware is ran automatically when the computer starts up

### Process Injection

- XOR decrypt Glagolitic (Inside the buffer that Glagolitic's contents was written into previously using `VirtualAlloc`) with a 14 character key `QGHA2Z5MLSRE76`

  ![IMAGE](/assets/img/Darkloader_sample/20.PNG)

- Read some information of Glagolitic buffer and the process

  ![IMAGE](/assets/img/Darkloader_sample/21.PNG)

- Initializes 3 strings: 

  - `C:\Windows\System32\svchost.exe`
  - `C:\Windows\Microsoft.NET\Framework\v2.0.50727\RegSvcs.exe`
  - `C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe`

- 1 of 3 process will be used for process injection, and through debugging I see that it used `svhost.exe`

  ![IMAGE](/assets/img/Darkloader_sample/22.PNG)

  ![IMAGE](/assets/img/Darkloader_sample/23.PNG)

- The process is started in `suspended` mode

  ![IMAGE](/assets/img/Darkloader_sample/24.PNG)

From that, it is very likely that the malware used **Process Hollowing** technique to inject the decrypted Glagolitic's buffer into `svhost.exe`

> *Probably an alternative method to this cause the malware doesnt really hollow the target process, but I cant find any other techniques that matches this*

After debugging, I can see that it is using multiple syscall functions resolved from `ntdll.dll` (Through a wrapper function) using the same method in [Resolve APIs dynamically](#resolve-apis-dynamically) by getting the address of the syscall stub from `resolve_ntdll_api(hash)` then calling the stub

We can inspect this by stepping inside the wrapper function, and then also step inside`resolve_ntdll_api(hash)` finally set a breakpoint after calling `resolve_function`

![IMAGE](/assets/img/Darkloader_sample/25.PNG)

![IMAGE](/assets/img/Darkloader_sample/26.PNG)

![IMAGE](/assets/img/Darkloader_sample/27.PNG)

I looked at some doucumentations online 

- https://www.ired.team/offensive-security/defense-evasion/retrieving-ntdll-syscall-stubs-at-run-time
- https://hfiref0x.github.io/sctables/X86_64/NT10_syscalls.html

> *The syscall ID is 2 bytes in length and starts 4 bytes into the function*

So in the picture: `027D2E70   B8 4A 00 00 00      ; mov eax, 0x4A`, this means that the syscall ID is `00 4A` which for Windows 10 version 22000 (Im debugging on this version) is `NtCreateSection`

I did the same for all the other wrapper functions and this is what the shellcode called:

- Syscall ID 42: `NtUnmapViewOfSection`

- Syscall ID 74: `NtCreateSection`

- Syscall ID 40: `NtMapViewOfSection` 

- Syscall ID 58: `NtWriteVirtualMemory`

- Syscall ID 82: `NtResumeThread`

Below is the process hollowing process:

![IMAGE](/assets/img/Darkloader_sample/28.PNG)

![IMAGE](/assets/img/Darkloader_sample/29.PNG)

- Firstly it gets the thread context and reads the image base address of `svchost.exe` in memory (is stored into `v72`). After that, it checks if the image base address of `svhost.exe` is inside they Glagolitic buffer

  - If not, call `NtCreateSection`

  - If true, call `NtUnmapViewOfSection`

    > Through debugging, `svhost.exe` image base is outside of the Glagolitic buffer so the program calls `NtCreateSection`

- `NtCreateSection` to create a section object (virtual memory block) with read, write, and execute permissions (64). It has the same size as `Glagolitic`. The section is created with `SEC_COMMIT` (0x08000000), meaning its pages are immediately committed in RAM

- `NtMapViewOfSection` is called twice

  - First time to map the previously created section into `svchost.exe`
  - Second time to map into the current process (used for copying Glagolitic payload into)
  - Both has read, write, execute permissions

- After that Glagolitic header and each sections is copied into the local view

- `NtWriteVirtualMemory` to update `svchost.exe`  original image base address to the address of mapped remote view (4 bytes)

- `SetThreadContext` and `NtResumeThread` to resume execution of `svchost.exe` which now will execute the stealer

> Little note here: `NtCreateSection` create a section object, according to the [offical document](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/section-objects-and-views) 
>
> *A section object represents a section of memory that can be shared. A process can use a section object to share parts of its memory address space (memory sections) with other processes*
>
> `NtMapViewOfSection` was called to map 2 different view to local and remote process but use the same `SectionHandle` which means that after copying Glagolitic payload into the local mapped view, **the same will happen to the remote view**. This makes the malware dont have to write the whole payload into the remote process

## The stealer

Since trying to dump the stealer from memory is complicated, I just take `Glagolitic` from `%TEMP%` and then XOR it with the given key `QGHA2Z5MLSRE76`

![IMAGE](/assets/img/Darkloader_sample/30.PNG)

The original file name is `gagtooth.exe` according to `Version Info` in its resources

The binary is written and compiled using Visual Basic version 6.0, we can also see this from the only imports `MSVBVM60.DLL`, this is the Visual Basic 6.0 runtime DLL

The stealer also contains a UPX packed DLL named `VBSQLite3.dll`. This DLL does not have any malicious exported functions, it only has standard SQLite functions that are used to read databases. But it is necessary for collecting account credentials, history, web data of browsers which the stealer will be using

![IMAGE](/assets/img/Darkloader_sample/31.PNG)

We can use `VB decompiler` and `x32dbg` to analyze

### Anti VM/Debugger

1. Before running the malicious code, the stealer first check the current processes to check for any debugger, monitoring processes,. if  theres 1 process that matches the list, the malware will exit. Also exit if there are less than 51 processes running

![IMAGE](/assets/img/Darkloader_sample/32.PNG)

- Heres the blacklist

```
fiddler, vxstream, tcpview, procexp, vmtools, autoit, wireshark, procmon, idaq, autoruns, apatedns, windbg
```

2. Check if storage < 60GB or RAM < 1GB or CPU cores < 2 or WMI, if any of this is smaller or doesnt exist => exit

    ![IMAGE](/assets/img/Darkloader_sample/33.PNG)

### Collecting computer information

Create a folder in `%APPDATA%\Microsoft\Windows\Templates\<COMPUTERNAME>-<USERNAME>` this will be used to exfiltrate stolen data

Check for `winsqlite3.dll` in the system, if the DLL does not exist the stealer will drop `VBSQLite3.dll` into `%PUBLIC%\Libraries` to use

![IMAGE](/assets/img/Darkloader_sample/34.PNG)

After that it tries to get the public ip of the user by connecting to `http://showip.net` or `http://www.mediacollege.com/internet/utilities/show-ip.shtml`

![IMAGE](/assets/img/Darkloader_sample/35.PNG)

### Collect browser credentials

1. Firefox

![IMAGE](/assets/img/Darkloader_sample/36.PNG)

2. Chromium browsers: username, passwords of websites; saved passwords; credit card info

![IMAGE](/assets/img/Darkloader_sample/37.PNG)

### Collect Mail and other services credentials

Read the registry data of Foxmail, Outlook, Office, FTPWare, Martin Prikryl, Pidgin, FileZilla, Thunderbird to collect username, password, email accounts, hosts

![IMAGE](/assets/img/Darkloader_sample/38.PNG)

![IMAGE](/assets/img/Darkloader_sample/39.PNG)

### Stroring and exfiltration

After each application data collected, it will write/append to  `%APPDATA%\Microsoft\Windows\Templates\<COMPUTERNAME>-<USERNAME>\<COMPUTERNAME>-<USERNAME>.txt`

- Heres the format

```
/*.*/
Username: smt
Password: smt
Application: Chrome
/*.*/
===============DARKCLOUD===============
```

For thunderbird and 163mail contacts they are saved into seperate files

![IMAGE](/assets/img/Darkloader_sample/45.PNG)

For exfiltrating the data there are 4 ways

- FTP

![IMAGE](/assets/img/Darkloader_sample/40.PNG)

- SMTP

![IMAGE](/assets/img/Darkloader_sample/41.PNG)

- HTTP: Send to gunsaldi[.]com

![IMAGE](/assets/img/Darkloader_sample/42.PNG)

- Telegram bot

![IMAGE](/assets/img/Darkloader_sample/43.PNG)

![IMAGE](/assets/img/Darkloader_sample/44.PNG)

## Summary

AutoIt executable has 3 embedded files: An .au3 script, Glagolitic (XORed payload), XORed shellcode 

`Glagoliticis` is dropped into `%TEMP%` folder, the AutoIt exe decrypt and execute shellcode 

Shellcode copies the AutoIt executable to `AppData/Local/underbalance/Myriopoda.exe`, persistence by creating `Myriopoda.vbs` in `shell::startup`, then change execution to `Myriopoda.exe` 

`Myriopoda.exe` decrypts `Glagolitic` then injects it into svchost.exe 

`svchost.exe` execute the stealer 

The stealer collects credentials from browsers,mail and ftp clients then send to C2 through FTP, SMTP, HTTP, Telegram Bot

## IOCs

- P Order © - PO232825.exe: 1267884aa681e9a3a5416ac2c2a67107

- Glagolitic: f1df5b527bfa2e6186bba0846501d33d

- Myriopoda.vbs: cf4a0ca4ca159f78bf670f0448c9e693

- gagtooth.exe: 3fb312b56a27b6822014851b8739bca0

- info@gunsaldi[.]com

- mail[.]gunsaldi[.]com

- admin[.]gunsaldi[.]com

- gunsaldi[.]com

- https[:]//api[.]telegram[.]org/bot6709893112[:]AAFihgPYk-sATVx8bmCllhChCbbXr5gGtcc/sendDocument
