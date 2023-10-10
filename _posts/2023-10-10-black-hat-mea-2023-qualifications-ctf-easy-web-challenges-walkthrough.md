---
title: Black Hat MEA 2023 Qualifications CTF Easy Web Challenges Walkthrough
date: 2023-10-10 10:30:00 +0200
categories:
  - ctf
  - blackhat
tags:
  - ctf
  - blackhat
  - web_applications
---

On October 8th, at 13:00 GMT, the Black Hat MEAQ Qualifications CTF commenced. Alongside my brilliant team, "creepers_249," I actively participated, putting forth our best efforts to secure those elusive flags.

I collaborated with my colleague Senku, focusing on the web category, and dedicated ourselves to conducting thorough reconnaissance and gaining a deep understanding of the applications.

In this blog post, I will recount our successful solutions to two of the straightforward web challenges.

## Authy

**Difficulty:** Easy

**Category**: WEB

### Description

I have just learned Golang and trying to build a small authentication platform with it. It's a simple API so it should be secure right ?

The source code in golang is included in the challenge. 

After review it I found out the most intersring parts as foolowing:

```go
func Registration(c echo.Context) error {
//snip 
	//hashing password (even it's a CTF, stick to the good habits)
	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 5)
	if err != nil {
		resp := c.JSON(http.StatusInternalServerError, helper.ErrorLog(http.StatusInternalServerError, " Error While Hashing Password", "EXT_REF"))
		return resp
	}
//snip 
}
func LoginController(c echo.Context) error {
//snip 
if len(password) < 6 {
	flag := os.Getenv("FLAG")
	res := &Flag{
		Flag: flag,
	}
	resp := c.JSON(http.StatusOK, res)
	log.Info()
	return resp
}
//snip
```

In the `Registration` function, the password is hashed by converting the provided password into a bcrypt hash. And notice this comment "**hashing password (even it's a CTF, stick to the good habits)**"

On the other hand, the flag is only displayed if the length of the password is less than 6 characters in the `LoginController` function. Additionally, it's worth mentioning that neither the `LoginController` nor the `Registration` functions are executed if a password with less than six characters is provided, resulting in an error message being displayed.

Application is running SQLite3 and use JWT to implements its cookies. Also, in the source code, there are two endpoints `/registration` and `/login`. So to be sure, I ran `gobuster` in directory mode.

```bash
$ gobuster dir -u http://abae0e83357c697e1b908.playat.flagyard.com/ -w /opt/wordlist/Hacking-APIs-main/Wordlists/api_superlist -t 2  
0 --timeout 30s    
===============================================================  
Gobuster v3.6  
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)  
===============================================================  
[+] Url:                     http://abae0e83357c697e1b908.playat.flagyard.com/  
[+] Method:                  GET  
[+] Threads:                 20  
[+] Wordlist:                /opt/wordlist/Hacking-APIs-main/Wordlists/api_superlist  
[+] Negative Status codes:   404  
[+] User Agent:              gobuster/3.6  
[+] Timeout:                 30s  
===============================================================  
Starting gobuster in directory enumeration mode  
===============================================================  
/login                (Status: 405) [Size: 33]  
/registration         (Status: 405) [Size: 33]  
Progress: 2298 / 2299 (99.96%)  
===============================================================  
Finished  
===============================================================
```

I then proceeded to interact with the application as intended, registering an account and subsequently logging in.

![Image](/assets/img/uploads/20231010041950.png)

![Image](/assets/img/uploads/20231010042049.png)

![Image](/assets/img/uploads/20231008165745.png)

Then I tried to crack JWT secret key, but I couldn't get anything.

```bash
$ sudo hashcat -a 0 -m 16500 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmaXJzdG5hbWUiOiIiLCJsYXN0bmFtZSI6IiIsInVzZXJuYW1lIjoic2t1bGxo  
YXQifQ.KD7nIK_Mg7O9yjotg6BB0NQeziv8TWRhieWtBbMavoo' /opt/wordlist/rockyou.txt  --show  
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmaXJzdG5hbWUiOiIiLCJsYXN0bmFtZSI6IiIsInVzZXJuYW1lIjoic2t1bGxoYXQifQ.KD7nIK_Mg7O9yjotg6BB0NQez  
iv8TWRhieWtBbMavoo:
```

After being stuck for a while 🤣, I read about Becypt hash algorithm and its implementation, with idea in my mind that in cryptography most of the time the problems are in implantation of algorithm not the algorithm itself. 

![Image](/assets/img/uploads/20231010042618.png)

And indeed the hash in the application starts with `$2a$`, So I looked to null byte in Unicode and it finally works!

![Image](/assets/img/uploads/20231008224010.png)

![Image](/assets/img/uploads/20231008224302.png)


## Warm Me Up

**Difficulty:** Easy

**Category**: WEB

### Description

The most secure login page you will ever come across.

The application is a simple login panel that requires a username, password, and OTP (One-Time Password) code for login. I started by examining the requests in Burp Suite. I noticed that it uses JWT and can be decoded to reveal the OTP code.
![Image](/assets/img/uploads/20231008225230.png)

I initiated a `gobuster` scan on the application:
```bash
$ gobuster dir -u http://abae0e83357c697e1b908.playat.flagyard.com/ -w /opt/wordlist/SecLists/Discovery/Web-Content/raft-small-d  
irectories.txt -t 20 --timeout 30s

/login                (Status: 200) [Size: 1898]  
/flag                 (Status: 200) [Size: 41]
```

When trying to access `/flag`, it displays the message **"You must be logged in to access the flag."**

I discovered that when you input a single quote `'` in either the username or password field, it returns a 500 response, indicating a potential SQL injection vulnerability. So, I tried some basic queries with the OTP supplied from the cookie, and voilà! It worked and displayed the flag.

**Payload:**

> *username:* `admin' UNION ALL SELECT NULL,NULL--`
> *password:* `' union select null--`

![Image](/assets/img/uploads/20231010044127.png)

![Image](/assets/img/uploads/20231010044024.png)

At the conclusion of the competition, with unwavering dedication from all team members, we achieved a commendable ranking of **#168**. Inshallah, we are optimistic about making it to the finals of Black Hat MEA in November.
