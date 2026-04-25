# TwoMillion Writeup

![TwoMillion](images/Pwned.png)

## 1. Reconnaissance

Let's perform an nmap scan to identify the open ports and services running on <MACHINE-IP>.

```bash
nmap -sC -sV -A <MACHINE-IP>

Host is up (0.43s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx
|_http-title: Did not follow redirect to http://2million.htb/
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   585.34 ms 10.10.14.1
2   587.81 ms 10.129.229.66

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Apr  9 07:32:10 2026 -- 1 IP address (1 host up) scanned in 166.26 seconds
```

Add the ip address to our hosts file

```bash
echo "<MACHINE-IP> 2million.htb" | sudo tee -a /etc/hosts
```

## 2. Enuumeration

I tried to register on the website but we need an invite code for it.
I tried to find subdomains but couldn't find any subdomain and moved to Directory Fuzzing

### 2.1 Directory Fuzzing

Perform a directory fuzzing scan using feroxbuster to identify and potential end points to gain a foothold

```bash
feroxbuster -u http://2million.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://2million.htb/
 🚩  In-Scope Url          │ 2million.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        7l       11w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
302      GET        0l        0w        0c http://2million.htb/logout => http://2million.htb/
200      GET       27l      201w    15384c http://2million.htb/images/favicon.png
405      GET        0l        0w        0c http://2million.htb/api/v1/user/login
200      GET        1l        8w      637c http://2million.htb/js/inviteapi.min.js
405      GET        0l        0w        0c http://2million.htb/api/v1/user/register
200      GET       94l      293w     4527c http://2million.htb/register
401      GET        0l        0w        0c http://2million.htb/api
200      GET       80l      232w     3704c http://2million.htb/login
200      GET       96l      285w     3859c http://2million.htb/invite
200      GET      245l      317w    28522c http://2million.htb/images/logofull-tr-web.png
200      GET      260l      328w    29158c http://2million.htb/images/logo-transparent.png
302      GET        0l        0w        0c http://2million.htb/home => http://2million.htb/
200      GET       46l      152w     1674c http://2million.htb/404
200      GET        5l     1881w   145660c http://2million.htb/js/htb-frontend.min.js
200      GET       13l     2458w   224695c http://2million.htb/css/htb-frontend.css
200      GET        8l     3162w   254388c http://2million.htb/js/htb-frontpage.min.js
200      GET       13l     2209w   199494c http://2million.htb/css/htb-frontpage.css
200      GET     1242l     3326w    64952c http://2million.htb/
```

We found an interesting endpoint `/js/inviteapi.min.js`

## 3. Initial Foothold

We can view the javascript file in browser tools or curl to view the contents

```bash
curl -X GET http://2million.htb/js/inviteapi.min.js
eval(function(p,a,c,k,e,d){e=function(c){return c.toString(36)};if(!''.replace(/^/,String)){while(c--){d[c.toString(a)]=k[c]||c.toString(a)}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('1 i(4){h 8={"4":4};$.9({a:"7",5:"6",g:8,b:\'/d/e/n\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}1 j(){$.9({a:"7",5:"6",b:\'/d/e/k/l/m\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}',24,24,'response|function|log|console|code|dataType|json|POST|formData|ajax|type|url|success|api/v1|invite|error|data|var|verifyInviteCode|makeInviteCode|how|to|generate|verify'.split('|'),0,{})) 
```

We can see there are `verifyInviteCode` and the code is obfuscated.

We can use chatgpt or online tools to get the actual code

```python
function verifyInviteCode(code) {
    var formData = { "code": code };

    $.ajax({
        type: "POST",
        dataType: "json",
        data: formData,
        url: '/api/v1/invite/verify',
        success: function(response) {
            console.log(response);
        },
        error: function(response) {
            console.log(response);
        }
    });
}

function makeInviteCode() {
    $.ajax({
        type: "POST",
        dataType: "json",
        url: '/api/v1/invite/how/to/generate',
        success: function(response) {
            console.log(response);
        },
        error: function(response) {
            console.log(response);
        }
    });
}
```

We found two api endpoints and we can send POST requestss to those endpoints

```bash
curl -X POST http://2million.htb/api/v1/invite/how/to/generate
{"0":200,"success":1,"data":{"data":"Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb \/ncv\/i1\/vaivgr\/trarengr","enctype":"ROT13"},"hint":"Data is encrypted ... We should probbably check the encryption type in order to decrypt it..."}  
```

We have ROT-13 encypted data, use cyberchef to decrypt or via command

```bash
echo "Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /ncv/i1/vaivgr/trarengr" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
In order to generate the invite code, make a POST request to /api/v1/invite/generate
```

Another api endpoint is revealed here and the decoded text suggests to make a POST request to that specific endpoint.

```bash
curl -X POST http://2million.htb/api/v1/invite/generate       
{"0":200,"success":1,"data":{"code":"VUtMWEMtNk5TTjAtVDkxNU4tVVY4WUE=","format":"encoded"}}                                                  
```

This successfully generated a code which is a base64 encoded string, Let's decode it 

```bash
echo "VUtMWEMtNk5TTjAtVDkxNU4tVVY4WUE=" | base64 -d
UKLXC-6NSN0-T915N-UV8YA                                                                               
```
Use the above code to register an account.

![Access Endpoint](images/Access-endpoint.png)

Since I couldn't find anything via browser, I switched to burp suite and started intercepting my traffc on the website.
I found an api endpoint via `generate` and `connection-pack` functions on Access endpoint

