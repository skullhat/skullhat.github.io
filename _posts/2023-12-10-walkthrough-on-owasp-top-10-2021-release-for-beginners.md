---
title: Walkthrough on OWASP Top 10 2021 Release for Beginners
date: 2023-12-10 01:30:00 +0200
categories:
  - owasp
  - web
tags:
  - web_applications
---
Today we'll discuss The Open Worldwide Application Security Project (OWASP) top 10 vulnerabilities in the web applications which noticed, collected and organized by volunteers who work in major technical companies and researchers from all over the glob. Ranked in the list every few years to help security professionals and decision makers to make the internet safer.

![Image](/assets/img/uploads/20231210213847.png]]

Each vulnerability in this list is just a blueprint to what the attack scenario is like and how an attacker could use that to affect the confidentiality, integrity and accessibility of the web application, so many unintended advantages can be gained or even worse the server can be remotely accessed or down which can cause in some cased a some million dollars to the company.

When engaging in bug bounty programs, it's essential to acknowledge that the most well-known vulnerabilities should not be your sole checklist. Instead, consider them as key indicators for understanding how the applications operate and as a starting point for your initial actions.

Let's dive in.

## A01:2021-Broken Access Control 

All websites have some kind of access control. Let's take for example the social network **R**. When you create an account you have a profile page and feed page which is sheared with all platform members. Sometimes you publish private posts with only your friends, or you have some personal information like email or birthdate, this is where the access control take place. 

If anyone at all could see this posts or show your personal information on your profile, this called a **broken access control**.

>**Definition**:
>
>	Access control enforces policy such that users cannot act outside their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of all data or performing a business function outside the user's limits.
>

Let's take another example, if on the platform R you found the endpoint `/adminPanle` then you try to access it and indeed to see can can use all the functionality of administrator with your normal user session there is huge security issue in this platform.

The previous example is for sure unrealistic (thanks god for that!), but for sure it shows us how important it's to design and make sure of the authorization process in our web application. Authorization make sure that everyone can view, add, edit and delete only what it's in their privileges, you can not just edit anyone name in the platform, or transfer fund of account don't own the examples are endless

Imagine the user Alex is trying to log in to his account profile in which way Alex can see his personal info. 

```php
if ($_GET['username']){ // if username parameter is set 
	$username = $_GET['username']; // store username in a variable
	getUserData($username); // the fuction return the user data of the provided username and show it in the page
} else {
	echo "User not provided!";
}
```

The requests to the server is something like:

```url
http://r.com/personal?username=alex
```

The username is passed as parameter to the application, so from attacker perspective if we changed the username parameter to `john` for example:

```url
http://r.com/personal?username=john
```

If it really shows us the private data of John, this is a **broken access control** vulnerability.

**Some other examples can be:**

- Bypassing access control checks by modifying the URL (parameter tampering or force browsing), internal application state, or the HTML page, or by using an attack tool modifying API requests.

- Accessing API with missing access controls for POST, PUT and DELETE.

- Elevation of privilege. Acting as a user without being logged in or acting as an admin when logged in as a user.

- Metadata manipulation, such as replaying or tampering with a JSON Web Token (JWT) access control token, or a cookie or hidden field manipulated to elevate privileges or abusing JWT invalidation.

### How to prevent the attacks:

Ok then, how we could fix the previous code? There is many things that we can add. Firstly, determine the privileges and types of access in out application to each user, such as:

- Start using session management mechanism.
- There is only normal user and admin user.
- The user can not view, edit or delete the personal info of other users only the user can do that to its own account.
- The user can not view other user private posts to their friends and only its and their friends.
- So on .…

```php
<?php
// perosnal page 
$cookieName = $_SESSION['username']
$cookieType = $_SESSION['userType']

if ($_GET['username'] === $cookieName){ // make sure that each user view only the page which authrized by its cookie
	$username = $_GET['username']; // store username in a variable
	getUserData($username); // the function return the user data of the provided username and show it in the page
} elseif ($cookieType === "admin") { // make sure that only admin can acess the admin panel based on his cookie
	viewAdminPanel($cookieName);
} else {
	Location: "403.php"
}
```

## A02:2021-Cryptographic Failures 

Cryptography is **the process of hiding or coding information so that only the person a message was intended for can read it**. For example, If there are people in the room, all of them talk English, but only two of them are talking Japanese. Can the third one who only talk English understand them, of course not! That's the key point of cryptography, is to transfer messages securely that no one other than the sender and receiver understand. 

In the web application we can't just let any one see and catch on what we send and receive because it could potentially contain our passwords, credit card numbers and emails that we can not let anyone else specially crackers who can use such info to take advantage of. We must make a secure channel between the user and the web server to transfer data or even store it in the databases.

Hypertext transfer protocol secure (HTTPS) is **the secure version of HTTP, which is the primary protocol used to send data between a web browser and a website**. HTTPS is encrypted in order to increase security of data transfer. 

Secure Hash Algorithm 256-bit, also known as SHA-256, is **a cryptographic hash function that converts text of any length to an almost-unique alphanumeric string of 256 bits**. The output is known as a hash value or hash. SHA-256 is used for cryptographic security to store password more securely in the databases.

In the crypto, the problems can be either: 

### 1. The algorithm we use:

Some algorithms are more secure than others, for example take the MD5 algorithm which was mainly used in the 90s and early yeas of 2000s, in 2006 Klima published an algorithm that could find a collision within one minute on a single notebook computer, which simply means that two words could have the same hash value and that's really a big problem so the most used hash these days is the SHA-512 which more complex than the MD5 which still used of checking the files sum before downloading it online.   

### 2. How we implement it: 

Some parsers and programming libraries are not implement the hashing or encrypting algorithm in secure way which threat the developer who use them in their code. 

One common cryptographic failure is the insecure storage of user passwords. Let's say a web application stores user passwords in plaintext or using weak encryption. This means that if an attacker gains access to the database where passwords are stored, they can easily retrieve and misuse user credentials.

### How to prevent the attacks:

- Make sure to encrypt all sensitive data at rest.
- Always use authenticated encryption instead of just encryption.
- Ensure that cryptographic randomness is used where appropriate, and that it has not been seeded predictably or with low entropy. Most modern APIs do not require the developer to seed the CSPRNG to get security.
- Avoid deprecated cryptographic functions and padding schemes, such as MD5, SHA1, PKCS number 1 v1.5 

## A03:2021-Injection 
  
Injection attacks in the context of web applications involve the malicious insertion or "injection" of untrusted data into the input fields or commands of an application, leading to unintended and potentially harmful consequences. These attacks typically exploit vulnerabilities in the application's handling of user inputs. One common type of injection attack is SQL injection, but there are others, such as command injection and cross-site scripting (XSS). Here are brief explanations of these injection attacks:

### Cross-site Scripting

Is the ability to inject malicious JavaScript code into the web application. Take this grocery store search page:

![Image](/assets/img/uploads/20230927160421.png]]

When you type what you're searching for it appears:

![Image](/assets/img/uploads/20230927160311.png]]

When the attacker search for this `img` tag
```html
<img src=x onerror=alert(1);>
```

![Image](/assets/img/uploads/20230927162647.png]]

Ops! it's show in the page but why ?

![Image](/assets/img/uploads/20230927160246.png]]

If we look closer to the JS code that handle the search, it just takes the search term and if it finds it is print it out, if not it prints the search term as HTML in the page. And it's our malicious code.

```js
if (matchingProducts.length > 0) {
    matchingProducts.forEach((product) => {
		resultsDiv.innerHTML += `
			<div>
				<h2>${product.name}</h2>
				<p>Price: $${product.price}</p>
			</div>
		`;
});

} else {
	resultsDiv.innerHTML += 'No matching products found.';
}
```

To make the code more secure, include [DOMPurify](https://github.com/cure53/DOMPurify) in your project. You can download and add it to your server, project or just add the `purify.js` from GitHub. Also, you can play around with it and control an allow-lists and block-lists.

```html
<script type="text/javascript" src="https://raw.githubusercontent.com/cure53/DOMPurify/main/dist/purify.js"></script>
```

Then fix the code, by purify the input of the user should be fine as initial step. 

```javascript
// Sanitize and display user input
resultsDiv.innerHTML = `Search results for: <b>${sanitizeInput(query)}</b><br><br>`;

// Sanitize input function
function sanitizeInput(input) {
    return DOMPurify.sanitize(input);
}
```

### SQL Injection

SQL Injection is a type of attack where an attacker manipulates a web application's SQL query by injecting malicious SQL code into user-input fields. This attack is particularly common when user inputs are directly concatenated into SQL queries without proper validation or parameterization.

Consider the following login page, the correct credentials are `admin:sunshine` so when entering them it shows a `Login Successful!` message.

![Image](/assets/img/uploads/20230927162839.png]]

And when using incorrect credentials, it shows `Login Failed!` message.

![Image](/assets/img/uploads/20230927162923.png]]

So what happened if we try injecting some SQL queries like:
```sql
admin'or 1=1-- -
```

![Image](/assets/img/uploads/20230927162956.png]]

Boom! It logged us in.

![Image](/assets/img/uploads/20230927163114.png]]

To see why that's the behavior, we should look into the source code notice that it takes two values not validating them then combine all of them in one variable query and excute them.
```php
$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
```

So when we inject the payload, it looks up for user `admin` then make a Boolean excretion always evaluated to true because `1==1` is always true and there is user called `admin` in `users` table.
```sql
SELECT * FROM users WHERE username=admin' or 1=1 -- -AND password=password!
-- this is a comment is MySQL
```

To prevent the attack, always sanitize user input to prevent SQL injection for each user controlled input.
```php
$username = mysqli_real_escape_string($conn, $username);
$password = mysqli_real_escape_string($conn, $password);
```

The `mysqli_real_escape_string(mysqli $mysql, string $string): string` Escapes special characters in a string for use in an SQL statement, taking into account the current char set of the connection which used to create a legal SQL string that you can use in an SQL statement. The given string is encoded to produce an escaped SQL string, taking into account the current character set of the connection.

### OS Command injection

OS Command Injection, also known as Command Injection or Shell Injection, is a type of security vulnerability where an attacker can execute arbitrary commands on a server by injecting malicious commands into an application. This attack takes advantage of situations where an application incorporates user-controllable data into a command that is then executed by the operating system.

Having this file control page as example, it controls the user directory allowing listing viewing and creating new files on that directory.

![Image](/assets/img/uploads/20230927164727.png]]

If we look closer the output is somehow similar with terminal font and way, what if it's really running some kind of terminal process in the background ?

![Image](/assets/img/uploads/20230927164805.png]]

Trying to inject this payload which combine the output, notice that indeed it's being printed on the screen.
```sh
; echo 'Hacked!'
```
![Image](/assets/img/uploads/20230927165155.png]]

The attack is caused by execute  `shell_exec()` which run system commands. To prevent it we sanitize and validate for anything other letters and numbers followed by file extension.
```php
// Validate and sanitize inputs to prevent command injection
	if (preg_match('/^[a-zA-Z0-9]+\.[a-zA-Z]{3,4}$/', $filename)) {
        $output = shell_exec("$command $filename");
        echo "<hr>";
        echo "<pre>Command Output:\n$output</pre>";
	} else {
		 echo "<p style='color: red;'>Invalid filename. Only alphanumeric characters and underscores are allowed.</p>";
}
```

After that we prevent the attack.

![Image](/assets/img/uploads/20230927165409.png]]

![Image](/assets/img/uploads/20230927165420.png]]
### How they appear?

User-supplied data is not validated, filtered, or sanitized by the application.

Dynamic queries or non-parameterized calls without context-aware escaping are used directly in the interpreter.

### How to prevent the attacks:

- The preferred option is to use a safe API, which avoids using the interpreter entirely, provides a parameterized interface, or migrates to Object Relational Mapping Tools (ORMs).  

    **Note:** Even when parameterized, stored procedures can still introduce SQL injection if PL/SQL or T-SQL concatenates queries and data or executes hostile data with EXECUTE IMMEDIATE or exec().

- Use positive server-side input validation. This is not a complete defense as many applications require special characters, such as text areas or APIs for mobile applications.

- For any residual dynamic queries, escape special characters using the specific escape syntax for that interpreter.  

    **Note:** SQL structures such as table names, column names, and so on cannot be escaped, and thus user-supplied structure names are dangerous. This is a common issue in report-writing software.

- Use LIMIT and other SQL controls within queries to prevent mass disclosure of records in case of SQL injection.


## A04:2021-Insecure Design

Design is the first stage on Software Development Life Cycle which focus on gathering the business requirement of the project and make a visual view of what it should like when it's up and running.

Secure design is a methodology that constantly evaluates threats and ensures that code is robustly designed and tested to prevent known attack methods. Usually these days it's responsibly of the DevSecOps engineer which involve in both designing and testing phases in the Software Development Life Cycle so make the code more secure and look for potential vulnerabilities before the application goes into the production.

We make a distinction between design flaws and implementation defects for a purpose, as they stem from different origins and require distinct remedies. While a well-thought-out design may still harbor implementation defects that expose vulnerabilities susceptible to exploitation, an insecure design cannot be rectified solely through flawless implementation. This is because, by definition, the necessary security measures were never established to safeguard against specific attacks.
 
Consider a cinema chain allows group booking discounts and has a maximum of fifteen attendees before requiring a deposit. Attackers could threat model this flow and test if they could book six hundred seats and all cinemas at once in a few requests, causing a massive loss of income.

Also, imagine a web application that relies solely on client-side sessions without implementing proper server-side validation or encryption. In this insecure design, sensitive information, such as user credentials or session tokens, might be stored on the client-side (e.g., in cookies) without adequate protection. This makes it susceptible to various attacks.

Main solution is to establish and use a secure development lifecycle with AppSec professionals to help evaluate and design security and privacy-related controls

## A05:2021-Security Misconfiguration

Misconfiguration is a huge problem nowadays, when using a new web server application, new control version solution or specific package implemented in the new feature of your application all of that can be an attack surface if it didn't configure securely.

For example, the New York State IT department unintentionally exposed its internal code repository online, granting unrestricted access to anyone. Cybersecurity firm *SpiderSilk* identified the exposed GitLab server, which housed projects containing confidential keys and passwords for state government systems. Notably, the server was set up to permit the creation of user accounts and login access by anyone.

Ok, if you install PhpMyAdmin to easily manage your database of your LAMP stack, it can be accessed on `/phpnyadmin` on your domain. You've done all of your develping and the website can accessed from all over the world. But you just missed that default credentials is `root:_blank_password_` and after an hour you find that your website is hacked Ops!

![Image](/assets/img/uploads/20231210061432.png]] 

So, you learned from that you did and hurry up to change both default username and password.
![Image](/assets/img/uploads/20231210062049.png]]

### How to prevent the attacks:

- A repeatable hardening process makes it fast and easy to deploy another environment that is appropriately locked down. Development, QA, and production environments should all be configured identically, with different credentials used in each environment. This process should be automated to minimize the effort required to set up a new secure environment.

- A minimal platform without any unnecessary features, components, documentation, and samples. Remove or do not install unused features and frameworks.

- A task to review and update the configurations appropriate to all security notes, updates, and patches as part of the patch management process


## A06:2021-Vulnerable and Outdated Components 

Vulnerable and outdated components" typically refer to software or hardware elements that are susceptible to security risks due to outdated versions or common known vulnerabilities (CVEs). This is a common concern in the field of cybersecurity, as attackers often target systems with known vulnerabilities to exploit weaknesses.

If you're running a blog using WordPress Core 5.0, I have important information to share. There's a security vulnerability known as CVE-2019-8943 that affects WordPress versions before 4.9.9 and 5.x before 5.0.1. This vulnerability could allow unauthorized access to your website.

Here's how it works: WordPress allows users to attach files to posts, and there's a specific field called "_wp_attached_file_" responsible for this. However, due to a flaw, this field can be manipulated to contain a malicious string, such as one ending with ".jpg?file.php". This manipulation opens the door for a potential attack.

If an attacker with author privileges can upload a specially crafted image file containing PHP code in its Exif metadata, they may be able to execute arbitrary code on your website. This means they could gain control over your site and potentially cause harm.

![Image](/assets/img/uploads/20231210063652.png]]

To safeguard your WordPress installation, it's crucial to update to a version that includes a fix for this vulnerability. Regularly updating your WordPress software helps ensure that you have the latest security patches and protects your site from potential threats.

> If you have some knowledge on it, you can try this attack scenario on this TryHackMe room.
> [TryHackMe | Blog](https://tryhackme.com/room/blog)

### How to prevent attacks 

- Optimize code: Remove unused dependencies, features, files, and documentation.

- Keep track: Regularly check versions of client-side and server-side components and monitor NVD for vulnerabilities or CVEs. 

- Secure sources: Obtain components only from official sources via secure links. Prefer signed packages to avoid malicious components.

- Stay updated: Monitor for unmaintained components and those lacking security patches. If patching isn't possible, consider deploying a virtual patch for monitoring, detection, or protection against potential issues.

## A07:2021-Identification and Authentication 

This category focus on authentication which you make sure of the identity of the user basic form of it is what you know like, username, email or password. What you have like electric  identity card, authentication flash drive or authentication app in the phone.

Without any doubt, it's one the most important part of of your application flow. If the user on *R* social platform can use any other user account. Or the back *Zee* which any user can use and transfer money from any account to its account that look like a mess! 

### Authentication VS. Authorization

Authentication is about verifying identity, ensuring that users are who they claim to be, while authorization is about granting appropriate permissions to authenticated users, specifying what actions or resources they are allowed to access. Both concepts are crucial for maintaining the security of web applications and systems. The relationship between them is in main two things:

- **Dependency:** Authentication typically precedes authorization. Before a system can determine what a user is allowed to do, it needs to verify their identity.

- **Order of Operations:** In the context of web security, the usual order is authentication first, followed by authorization. Once a user is authenticated, the system checks their permissions to decide what actions they are authorized to perform.

For **example,** If you think of a secure building, authentication is like showing your ID at the entrance to prove you are who you say you are. Authorization, on the other hand, is like the security personnel deciding which areas of the building you are allowed to access based on your credentials.

Let's consider this login page. The credentials are `user:passwors` as testing page. 

> *Note:*
> In a real-world scenario, you should validate the credentials securely and have more secure credentials.

![Image](/assets/img/uploads/20231210074321.png]]

Noticing that before login in we have some session cookie. 
![Image](/assets/img/uploads/20231210073924.png]]

When we enter the default credential and refresh the page it's still the same value even though we're loged in, that is like when you and you twin swich on exam test there is no way to deffreaintat who is the user and who is not!

![Image](/assets/img/uploads/20231210074257.png]]

```php
function is_authenticated()
{
    return isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true;
}

<?php if (is_authenticated()) : ?>
    <p>Welcome, <?php echo $_SESSION['username']; ?>! <a href="?logout=true">Logout</a></p>
<?php else : ?>
    <form method="post" action="">
    ...
    </from>
```

In this example, after a successful login, the session identifier is not regenerated. An attacker could fixate the session by providing the victim with a link containing the session ID. Ideally, you should regenerate the session ID upon successful login using `session_regenerate_id(true)`.

### How to prevent attacks 

1. **Multi-Factor Authentication (MFA):** Implement MFA to enhance security by requiring users to provide multiple forms of identification, preventing automated attacks like credential stuffing, brute force, and stolen credential reuse.

2. **Default Credentials:** Avoid deploying with default credentials, especially for admin users, to reduce the risk of unauthorized access.    

3. **Weak Password Checks:** Incorporate weak password checks, such as validating new passwords against a list of commonly used weak passwords, to enhance overall password security.

4. **Password Policies:** Align password policies, including length, complexity, and rotation, with guidelines from NIST 800-63b to implement modern, evidence-based password practices.

5. **Hardened Registration and Recovery Paths:** Strengthen registration, credential recovery, and API pathways against account enumeration attacks by maintaining consistent messages for all outcomes, minimizing information leakage.

6. **Account Lockout and Logging:** Limit or progressively delay failed login attempts to deter brute force attacks. Log all failures and alert administrators when suspicious activities, like credential stuffing, are detected, while avoiding potential denial of service scenarios.

7. **Secure Session Management:** Use a server-side, secure session manager that generates a new random session ID with high entropy after login. Ensure the session identifier is not exposed in the URL, securely stored, and invalidated after logout, idle periods, and absolute timeouts to mitigate session-related vulnerabilities.

## A08:2021-Software and Data Integrity Failures

Software and data integrity failures occur when code and infrastructure lack safeguards against integrity violations. An instance of this vulnerability arises when an application depends on plugins, libraries, or modules sourced from untrusted repositories, plugins, and content delivery networks (CDNs). An insecure Continuous Integration/Continuous Deployment (CI/CD) pipeline increases the risk of unauthorized access, insertion of malicious code, or compromise of the system.

Additionally, many applications now incorporate auto-update functionality, wherein updates are downloaded without adequate integrity verification and are applied to previously trusted applications. This creates a potential avenue for attackers to upload their own updates, which can then be distributed and executed on all installations.

Another scenario involves encoding or serializing objects or data into a structure that is visible and modifiable by attackers, making it susceptible to *insecure deserialization.*

Insecure deserialization refers to a security vulnerability where an application blindly trusts serialized data without proper validation, leading to potential exploits by attackers. Here's a simplified example:

Consider a web application that uses serialized data to store user preferences. The serialized data might look like this:

```python
user_preferences = "O:8:\"stdClass\":1:{s:5:\"theme\";s:7:\"default\";}"
```

In this PHP serialized data, it represents an object of the stdClass class with a single property "theme" set to "default". During the deserialization process, the application reconstructs the object based on this serialized data.

Now, imagine an attacker intercepts and manipulates the serialized data before it reaches the application:

```python
user_preferences = "O:8:\"stdClass\":1:{s:5:\"theme\";s:6:\"attack\";}"
```

The attacker changes the "theme" property to "attack." If the application blindly deserializes this manipulated data without proper validation, it might inadvertently set the user's theme to a malicious value.

In a real-world scenario, this could lead to serious consequences, such as remote code execution, as attackers may inject malicious code within the serialized data, taking advantage of the application's trust in the deserialization process. To prevent this, applications should implement proper validation and integrity checks during deserialization.

### How to prevent attack

- Implement digital signatures or similar mechanisms to authenticate the origin and integrity of software or data.

- Validate that libraries and dependencies, such as those from npm or Maven, are sourced from trusted repositories. For heightened security, consider maintaining an internal repository that is thoroughly vetted.

- Utilize a software supply chain security tool, like OWASP Dependency Check or OWASP CycloneDX, to ensure that components do not contain known vulnerabilities.

- Establish a robust review process for code and configuration changes to minimize the risk of introducing malicious code or configuration into the software pipeline.

- Avoid sending unsigned or unencrypted serialized data to untrusted clients unless accompanied by an integrity check or digital signature to identify tampering or replay of the serialized data.

## A09:2021-Security Logging and Monitoring Failures

The absence of comprehensive logging and monitoring renders breaches virtually undetectable. Inadequate logging, deficient detection mechanisms, monitoring lapses, and ineffective response strategies manifest when:

1. Events subject to audit, like logins, failed logins, and critical transactions, remain unlogged.

2. Warning and error conditions produce either no, insufficient, or unclear log messages.

3. Applications and APIs lack vigilant monitoring for signs of suspicious activity within their logs.

4. Logs are exclusively stored in local repositories.

5. Adequate alerting thresholds and effective response escalation procedures are either absent or ineffective.

6. Penetration testing and scans conducted by dynamic application security testing (DAST) tools, such as OWASP ZAP, fail to trigger alerts.

7. The application is incapable of identifying, escalating, or promptly alerting for active attacks in real-time or near real-time scenarios.

So the best practice is to combine both active logging of important failures, error messages, high traffic from specific source or even the system warnings in way that fit your need and business logic.

### How to prevent the attacks

- Ensure all login, access control, and server-side input validation failures can be logged with sufficient user context to identify suspicious or malicious accounts and held for enough time to allow delayed forensic analysis.

- Ensure that logs are generated in a format that log management solutions can easily consume.

- Ensure log data is encoded correctly to prevent injections or attacks on the logging or monitoring systems.

- Ensure high-value transactions have an audit trail with integrity controls to prevent tampering or deletion, such as append-only database tables or similar.

- DevSecOps teams should establish effective monitoring and alerting such that suspicious activities are detected and responded to quickly.

## A10:2021-Server-Side Request Forgery

SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send a crafted request to an unexpected destination, even when protected by a firewall, VPN, or another type of network access control list (ACL).

```php
<?php
$url = $_GET['url'];
$data = file_get_contents($url);
echo $data;
?>
```

An attacker might send a request like `http://r.com/page.php?url=http://internal-resource` to access an internal resource that the server can reach.

### How to Prevent Attacks

Developers can prevent SSRF by implementing some or all the following defense in depth controls:

### **From Network layer**

- Segment remote resource access functionality in separate networks to reduce the impact of SSRF
    
- Enforce “deny by default” firewall policies or network access control rules to block all but essential intranet traffic.  

### **From Application layer:**

- Sanitize and validate all client-supplied input data

- Enforce the URL schema, port, and destination with a positive allow list

- Do not send raw responses to clients

- Disable HTTP redirections

  
In conclusion, navigating through the OWASP Top 10 Walkthrough has provided valuable insights into the most critical web application security risks that organizations face today. By addressing vulnerabilities outlined in this guide, developers and security professionals can fortify their applications against common threats, ultimately fostering a more resilient and secure online environment.

## References

- https://owasp.org/Top10/
- [All Web Security Academy topics | Web Security Academy - PortSwigger](https://portswigger.net/web-security/all-topics)
- [Cryptographic Failures Vulnerability - Examples & Prevention (crashtest-security.com)](https://crashtest-security.com/owasp-cryptographic-failures/)

