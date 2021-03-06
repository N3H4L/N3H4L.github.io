---
title: October - HackTheBox
published: true
---
![](assets/img/october-htb/htb-oct-icon.png)

**Hey Guys!** In this blog, we are going to pwn **October** from [HackTheBox](https://www.hackthebox.eu). Before we begin, let me give you a brief overview of what exactly we are going to do :
*   First, we scan the box to find a laravel web application running October CMS.
*   Then we go beyond the admin panel of the CMS after which we upload a php reverse shell.
*   That will give us the access as a low privileged user.
*   Then we escalate our privileges to root by a classic binary exploitation.

With that said, let us begin.

# [](#header-1)SCANNING :
![](assets/img/october-htb/htb-oct-nmap-1.png)

A short and quick **nmap** scan reveals ports 22 and 80 to be open.

![](assets/img/october-htb/htb-oct-nmap-2.png)

By the port numbers, as you might have guessed, we have **OpenSSH 6.6.1p1** running on port 22 and **Apache httpd 2.4.7** on port 80.

I do not think we need to know more than this in the scanning phase. Let us now move to enumeration.

# [](#header-1)ENUMERATING HTTP:    
Since HTTP has a large attack vector, let us begin with that first.

By visiting the IP through the browser, we are greeted with the below page:

![](assets/img/october-htb/htb-oct-web-1.png)

By the caption of the heading, we now know this is presented by **October CMS**. There are 3 sub-pages also shown in the navigation bar: **Account**, **Blog** and **Forum**.

Finding nothing interesting here, I decided to fuzz for some directories.

![](assets/img/october-htb/htb-oct-web-2.png)

I am using **wfuzz** to fuzz with some common wordlists of **dirb**.

The **backend** directory looks juicy. Let us check what it has for us.

![](assets/img/october-htb/htb-oct-web-3.png)

We are redirected to **/backend/backend/auth/signin** that is the **admin** login page for **October CMS**. I tried some common credentials that I usually try in such situations like :

*   admin:admin
*   admin:password
*   admin:october
*   root:root
*   root:password
*   root:october

However, luckily, the **admin:admin** worked and we are in.

![](assets/img/october-htb/htb-oct-nmap-4.png)

# [](#header-1)EXPLOITATION:

If we enumerate a little more, we find an upload functionality in **Media** tab.

![](assets/img/october-htb/htb-oct-web-5.png)

Now you know what exactly we have to do ;) Yup, let us upload a **php reverse shell** with **.php5** extension (since there is a file with php5 extension, the box is probably accepting php5 extension files only).

![](assets/img/october-htb/htb-oct-web-6.png)

As you can see, our shell is uploaded. Now we just need to set up a listener and trigger the shell by the link on the right panel.

![](assets/img/october-htb/htb-oct-shell-1.png)

We now have a shell as **www-data**. You can read the user flag from the user’s home directory.

# [](#header-1)PRIVILEGE ESCALATION:

Let us check for **SUID** set files.

![](assets/img/october-htb/htb-oct-shell-2.png)

Of all the files, the **/usr/local/bin/ovrflw** is odd.

![](assets/img/october-htb/htb-oct-shell-3.png)

The file is owned by **root**. This might be our way to **root**. Let us export it in our local box and play with it a bit.

![](assets/img/october-htb/htb-oct-shell-4.png)

As you can see, when we run the binary with no **command line arguments**, it gives us the message to give one string as input. Next, we run again with a test string, but we see no visual response. However, if we give a sufficiently large input, it causes a **segmentation fault**, proving that there is indeed a **buffer overflow**.

Let us now examine the binary under **GDB**.

![](assets/img/october-htb/htb-oct-shell-5.png)

We load the binary in **GDB** and look for the security enabled in the binary. As you can see, the **NX** bit is disabled. So we can not put a shellcode and execute it from the stack.

In such cases,we can try another technique called **ret-to-libc** technique. In this, we redirect the execution by overwriting the **return address** to **libc** function like **system()** with argument **‘/bin/sh’** to obtain shell.

But for that, we need to find the **offset** to overwrite the **return address**. Let us do that first.

![](assets/img/october-htb/htb-oct-shell-6.png)

I have created a **cyclic pattern** of length **200** and provide it as **CLI** to the binary in GDB. The **Segmentation Fault** occurs at **0x62616164** (**‘daab’**).

![](assets/img/october-htb/htb-oct-shell-7.png)

With the **EIP** value, we determined the **offset** to be at **112**.

Now its time to find the address for **system**, **exit** and **/bin/sh** in libc.

![](assets/img/october-htb/htb-oct-shell-8.png)

We used the **ldd** utility to find the address for **libc** shared library which is at **0xf7d3d000**. Then we used **readelf** to get the **offset** for **system**, **exit** and **/bin/sh** from **libc**. However, that is just **offset**. The actual address would be :

### &lt;addr of libc&gt; + &lt;offset&gt;

Now that we know the addresses, its time to build our fake function call.

This would take the form :

### &lt;112 A’s&gt; + &lt;system function addr&gt; + &lt;exit function addr&gt; + &lt;'/bin/sh' string addr&gt;

The **return address** is first overwritten with **system** function address so the control flows there, then **exit** function address is given as the new return address, next, the argument for **system** function is given which is **‘/bin/sh’**.

Let us build the exploit and run it.

![](assets/img/october-htb/htb-oct-shell-9.png)

Wait! We are supposed to get a shell. Instead we got a **segmentation fault**. Let us debug that and find where exactly we went wrong.

![](assets/img/october-htb/htb-oct-shell-10.png)

When we again check the **libc** address, we find a different address from the one we found a few minutes ago. This indicates that the **ASLR** is on. We verified the same by checking for ASLR.

**ASLR** means **Address Space Layout Randomization** which is responsible for making the address of stack, heap, shared libraries and executables in the memory to be random.

Now, how we bypass that? One way is to run the binary in a while loop so that it increases the probability of our exploit to work. Let us try that out.

![](assets/img/october-htb/htb-oct-shell-11.png)

![](assets/img/october-htb/htb-oct-shell-12.png)

As you can see, we are successful to pop a **shell**.

Now, playtime on the local box is over. Let us do the same thing on the remote box.

![](assets/img/october-htb/htb-oct-shell-13.png)

And we succeeded to elevate our privileges to **root**. You can read the root flag now too.

So that was it for **October box**. I hope you liked the write-up.

**Thanks** for reading this far. I will see you in the next one. **Peace**.
