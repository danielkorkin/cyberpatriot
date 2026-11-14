# CyberPatriot Linux Mint 21 — Cheat Sheet

Run everything as root (`sudo -i`). Mint 21 is Ubuntu 22.04-based.

## Golden Rules

- [ ] **Read the README first** (authorized users/admins, required services and software). It overrides everything below.
- [ ] Answer **Forensics Questions before deleting anything.**
- [ ] Back up before editing: `cp -a FILE FILE.bak`
- [ ] Keep a **root shell open** while editing SSH, PAM, sudoers, or the firewall. Test from a second terminal.
- [ ] Never touch `/opt/CyberPatriot*`, the README, ScoringReport, or Forensics Question files.
- [ ] Log every change (time, what, file, before → after).

**Order:** README + Forensics → Users → Password policy → Updates → Firewall → System config → Software → Processes & persistence → Prohibited files → Check the scoring report.

---

## 1. Users & Groups

**Audit**

```bash
# human users
getent passwd | awk -F: '$3>=1000 && $3<=60000 {print $1,$3,$7}'

# UID 0 (only root is allowed)
awk -F: '$3==0 {print $1}' /etc/passwd

# empty passwords
awk -F: '$2=="" {print $1}' /etc/shadow

# system accounts with a login shell
awk -F: '$3<1000 && $3!=0 && \
  $7 !~ /(nologin|false|sync|halt|shutdown)$/ {print $1,$7}' /etc/passwd

getent group sudo admin     # admins
passwd -S -a                # P=set  L=locked  NP=none
chage -l USER               # aging detail
```

**Change**

```bash
useradd -m -s /bin/bash NEW && passwd NEW     # add user
userdel -r USER                               # delete user + home
pkill -KILL -u USER; userdel -f -r USER       # if "used by process"
gpasswd -a USER sudo                          # grant admin
gpasswd -d USER sudo                          # revoke admin (also try: admin)
passwd USER                                   # set password
passwd -e USER                                # force change at next login
usermod -L USER                               # lock   (-U to unlock)
usermod -s /usr/sbin/nologin USER             # fix system account shell
```

- [ ] Unauthorized users deleted
- [ ] No extra UID 0
- [ ] Admins match README
- [ ] No empty passwords; strong password on every account
- [ ] Don't delete or lock root or yourself

---

## 2. Password & Login Policy

**Aging** — `/etc/login.defs` (affects NEW accounts only)

```bash
sed -i -E \
  -e 's/^[[:space:]]*PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/' \
  -e 's/^[[:space:]]*PASS_MIN_DAYS.*/PASS_MIN_DAYS\t7/' \
  -e 's/^[[:space:]]*PASS_WARN_AGE.*/PASS_WARN_AGE\t14/' /etc/login.defs

# apply to existing users
for u in $(awk -F: '$3>=1000 && $3<=60000 {print $1}' /etc/passwd); do
  chage -M 90 -m 7 -W 14 "$u"
done
```

**Length & history** — edit `/etc/pam.d/common-password`

```
password requisite pam_pwquality.so retry=3 minlen=10
password [success=1 default=ignore] pam_unix.so obscure use_authtok \
    try_first_pass yescrypt remember=5
```

(`apt install libpam-pwquality` if missing. Keep each PAM entry on one line in the real file.)

**No blank passwords**

```bash
sed -i -E '/pam_unix\.so/ s/[[:space:]]+nullok(_secure)?//' /etc/pam.d/common-auth
```

**Lockout (faillock)** ⚠ can lock everyone out — test in a second terminal.

`/etc/security/faillock.conf`:

```
deny = 5
unlock_time = 900
```

`/etc/pam.d/common-auth` — wrap the `pam_unix.so` line and raise its `success=N` by 1:

```
auth  required                    pam_faillock.so preauth
auth  [success=2 default=ignore]  pam_unix.so ...      # was success=1
auth  [default=die]               pam_faillock.so authfail
```

`/etc/pam.d/common-account` — above the `pam_unix.so` line:

```
account required pam_faillock.so
```

Unlock a user: `faillock --user USER --reset`

---

## 3. Updates

```bash
apt update && apt full-upgrade -y
```

Also enable automatic updates (Update Manager → Preferences, or `apt install unattended-upgrades`).

---

## 4. Firewall (UFW)

```bash
cp -a /etc/ufw /root/ufw.bak
cp -a /etc/default/ufw /root/default-ufw.bak

ss -tulpn                  # what is listening; compare with README
ufw status verbose
ufw status numbered

ufw allow 22/tcp           # ONLY what the README requires
ufw limit 22/tcp           # rate-limited alternative for SSH
ufw delete allow 21/tcp    # or: ufw delete N
ufw default deny incoming
ufw default allow outgoing
ufw --force enable
systemctl enable ufw
```

| Service  | Port    | Service       | Port                      |
| -------- | ------- | ------------- | ------------------------- |
| SSH      | 22/tcp  | Samba         | 139,445/tcp + 137,138/udp |
| FTP ⚠    | 21/tcp  | CUPS          | 631/tcp                   |
| Telnet ⚠ | 23/tcp  | MySQL         | 3306/tcp                  |
| SMTP     | 25/tcp  | PostgreSQL    | 5432/tcp                  |
| DNS      | 53      | POP3 / IMAP   | 110 / 143/tcp             |
| HTTP     | 80/tcp  | POP3S / IMAPS | 995 / 993/tcp             |
| HTTPS    | 443/tcp | RDP ⚠ / VNC ⚠ | 3389 / 5900/tcp           |

Port lists and ranges need a protocol, e.g. `ufw allow 6000:6010/tcp`. If connected by SSH, allow that port **first**.

- [ ] UFW active
- [ ] Default incoming = deny
- [ ] Only README services open

---

## 5. System Config

**SSH** — `/etc/ssh/sshd_config` (also check `/etc/ssh/sshd_config.d/*.conf`; drop-ins win)

```bash
sshd -T | grep -Ei \
  'permitrootlogin|passwordauthentication|permitemptypasswords|x11forwarding|maxauthtries'
```

| Setting                  | Value                                                 |
| ------------------------ | ----------------------------------------------------- |
| `PermitRootLogin`        | `no`                                                  |
| `PasswordAuthentication` | `no` (⚠ only if the README doesn't need password SSH) |
| `PermitEmptyPasswords`   | `no`                                                  |
| `X11Forwarding`          | `no`                                                  |
| `MaxAuthTries`           | `4`                                                   |

```bash
sshd -t && systemctl reload ssh
```

**sysctl** — append to `/etc/sysctl.conf` (remove older duplicates), then run `sysctl -p`

```
net.ipv4.ip_forward = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.rp_filter = 1
kernel.randomize_va_space = 2
```

**LightDM** — no guest, no autologin

```bash
grep -rnE 'allow-guest|autologin' /etc/lightdm/
```

Under `[Seat:*]` (in `lightdm.conf` or `lightdm.conf.d/*.conf`): set `allow-guest=false` and delete any `autologin-user=` line.

**sudoers**

```bash
grep -rnE 'NOPASSWD|!authenticate' /etc/sudoers /etc/sudoers.d/

# all active lines; only root, %sudo, %admin should have ALL
grep -vE '^\s*(#|$)' /etc/sudoers /etc/sudoers.d/*

visudo                          # edit safely
visudo -cf /etc/sudoers.d/FILE  # syntax check
```

Comment out suspicious lines; check the README first.

**Permissions**

```bash
ls -l /etc/shadow                              # should be root:shadow, mode 640
find / -xdev -type f -perm -0002 2>/dev/null   # world-writable files
```

---

## 6. Unauthorized Software

**Find**

```bash
# hacking tools
dpkg -l | grep -Ei 'nmap|zenmap|wireshark|tshark|john|hydra|ophcrack|aircrack|\
hashcat|nikto|sqlmap|netcat|ncat|ettercap|dsniff|medusa|fcrackzip|pdfcrack|\
kismet|yersinia|crunch|netdiscover|masscan|wifite|reaver|macchanger|dnsrecon|\
cewl|hping3|nbtscan|snort|metasploit|burpsuite'

# P2P
dpkg -l | grep -Ei 'deluge|qbittorrent|transmission|frostwire|amule|ktorrent|vuze'

# games
dpkg -l | grep -Ei 'aisleriot|gnome-(mines|sudoku|mahjongg|chess)|quadrapassel|\
supertux|freeciv|wesnoth|minetest|0ad|openarena|xonotic|steam|lutris|kpat'
dpkg-query -W -f='${Package} ${Section}\n' | awk '$2 ~ /games/'

# servers (keep if the README needs them)
dpkg -l | grep -Ei 'vsftpd|proftpd|telnetd|xinetd|rsh-server|tftpd|apache2|nginx|\
samba|nfs-kernel|bind9|postfix|dovecot|mysql-server|snmpd|x11vnc|tightvnc|openssh-server'

snap list
flatpak list --app

# unpackaged software (dpkg -S FILE shows the owning package)
ls -la /opt /usr/local/bin /usr/local/sbin /usr/games
```

**Manually installed, not part of the original install**

```bash
zcat /var/log/installer/initial-status.gz | awk '/^Package:/{print $2}' | sort -u > /root/base.txt
apt-mark showmanual | sort > /root/manual.txt
comm -13 /root/base.txt /root/manual.txt

# who installed what, and when
zcat -f /var/log/apt/history.log* | grep -E '^(Start-Date|Commandline|Install):'
```

**Remove** (simulate first and look for unintended extras)

```bash
apt-get -s purge PKG
apt-get purge -y PKG
apt-get autoremove --purge -y
snap remove --purge NAME
flatpak uninstall -y --delete-data APP.ID
```

**Never purge:** sudo, apt, dpkg, bash, coreutils, login, passwd, libc6, systemd*, dbus*, grub-_, mint-_, linux-_, ubuntu-_, cinnamon*, lightdm*, xorg*, network-manager*.

**Check the README before removing:** firefox, chromium, thunderbird, libreoffice, openssh-server, apache2, samba.

- [ ] Hacking tools, games, P2P gone
- [ ] Needed servers kept; unneeded removed
- [ ] `/opt`, `/usr/local`, snap, flatpak reviewed

---

## 7. Processes & Persistence

**Processes**

```bash
ps -eo pid,ppid,user,pcpu,args --sort=-pcpu | head -40
ss -tulpn                         # odd high ports, unknown listeners

# running from temp/home, or binary deleted
ls -l /proc/*/exe 2>/dev/null | grep -E 'deleted|/tmp/|/dev/shm/|/home/|/root/'

PID=1234
ls -l /proc/$PID/exe /proc/$PID/cwd
tr '\0' ' ' < /proc/$PID/cmdline; echo
dpkg -S "$(readlink /proc/$PID/exe)"    # no package = suspicious
systemctl status $PID                   # which service owns it
```

**Red flags**

- Names: `nc ncat netcat socat nmap john hydra hashcat aircrack-ng ettercap medusa xmrig minerd sqlmap nikto msfconsole`
- Command lines containing `/dev/tcp/`, `bash -i`, `mkfifo`, `base64 -d | sh`, or `curl|wget … | sh`
- Anything run from `/tmp`, `/dev/shm`, or a home folder; hidden-name binaries

**Persistence — check all of these**

```bash
# cron
for u in $(cut -d: -f1 /etc/passwd); do
  echo "== $u"; crontab -l -u $u 2>/dev/null
done
cat /etc/crontab
ls -la /etc/cron.d /etc/cron.{hourly,daily,weekly,monthly}

# systemd (dpkg -S FILE: no owner = suspicious)
systemctl list-units --type=service --state=running
systemctl list-unit-files --state=enabled
systemctl list-timers --all
ls -la /etc/systemd/system/*.service /etc/systemd/system/*.timer \
  /usr/local/lib/systemd/system ~/.config/systemd/user 2>/dev/null

# autostart / boot
ls -la /etc/xdg/autostart /home/*/.config/autostart /etc/init.d /etc/profile.d
cat /etc/rc.local

# ssh keys (unknown key = backdoor)
cat /home/*/.ssh/authorized_keys* /root/.ssh/authorized_keys* 2>/dev/null

# shell startup files
grep -nE 'curl |wget |/dev/tcp|nohup |/tmp/|/dev/shm/|nc |socat |bash -i|mkfifo' \
  /home/*/.bashrc /home/*/.profile /home/*/.bash_profile \
  /etc/profile /etc/bash.bashrc /root/.bashrc 2>/dev/null
```

**Neutralize** — remove persistence **first**, then kill, or it respawns

```bash
B=/root/backup-$(date +%s); mkdir -p $B; cp -p FILE $B/
sed -i 'Ns/^/# disabled: /' FILE      # comment out line N
crontab -e -u USER                    # edit a user's crontab
systemctl stop NAME
systemctl disable NAME
systemctl mask NAME
mv FILE $B/                           # whole-file entries (init.d, autostart)
kill PID; sleep 1; kill -9 PID
```

Network services to compare against the README: sshd, vsftpd, proftpd, apache2, nginx, mysqld, postgres, smbd, nmbd, telnetd, xinetd, cupsd, postfix, dovecot, named, snmpd, x11vnc, avahi-daemon.

- [ ] Suspicious processes explained or killed
- [ ] cron, systemd, autostart, rc.local, ssh keys, shell rc reviewed
- [ ] README services still running

---

## 8. Prohibited Files

**Find**

```bash
R="/home /root /tmp /var/tmp /dev/shm /opt /srv /var/www /media /mnt"

# media
find $R -type f -regextype posix-extended -iregex \
  '.*\.(mp3|mp4|avi|mkv|mov|wmv|flv|webm|m4a|aac|flac|ogg|wav|wma|mpg|mpeg|3gp)$' 2>/dev/null

# large images in home folders
find /home -type f -size +1M \
  \( -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' -o -iname '*.gif' \)

# game ROMs
find $R -type f -regextype posix-extended -iregex \
  '.*\.(nes|sfc|smc|gba|gb|gbc|n64|z64|nds)$' 2>/dev/null

# game folders
find $R /usr/games /usr/share/games -type d \
  \( -iname games -o -iname 'steam*' -o -iname '.steam*' -o -iname '*minecraft*' \
     -o -iname roms -o -iname 'emulator*' \) 2>/dev/null

# password lists and hashes
find $R -type f \( -iname 'rockyou*' -o -iname '*wordlist*' -o -iname '*passlist*' \
  -o -iname '*password*.txt' -o -iname '*password*.lst' -o -iname '*.lst' \
  -o -iname john.pot -o -iname '*.potfile' -o -iname '*.hash*' \
  -o -iname 'shadow*' -o -iname 'passwd*' \) 2>/dev/null

# executables and shell files in temp dirs
find /tmp /var/tmp /dev/shm -type f \( -perm /111 -o -iname '*.sh' -o -iname '*.py' \
  -o -iname '*.pl' -o -iname '*.php' -o -iname '*.elf' \) 2>/dev/null

# hidden executables in home folders
find /home /root -maxdepth 2 -type f -name '.*' -perm /111 2>/dev/null
```

**Backdoor patterns and sensitive text**

```bash
# reverse-shell / download-and-run patterns in code files
PAT='/dev/tcp/|(nc|ncat|netcat|socat) |bash -i|mkfifo|pty\.spawn'
PAT="$PAT|base64 +-d *\| *(ba)?sh|(curl|wget)[^|]*\| *(ba)?sh"
find $R -type f -size -1024k \
  \( -iname '*.sh' -o -iname '*.py' -o -iname '*.pl' -o -iname '*.php' \) -print0 2>/dev/null |
  xargs -0 -r grep -lIE "$PAT"

# files mentioning passwords, credit cards, SSNs (names only)
find /home /root -type f -size -5120k ! -path '*/.*' -print0 2>/dev/null |
  xargs -0 -r grep -lIiE \
  'password|passwd|credit|\bssn\b|social security|[0-9]{3}-[0-9]{2}-[0-9]{4}'
```

**Inspect:** `stat FILE; file FILE; head -25 FILE`

**Quarantine instead of deleting when unsure**

```bash
Q=/root/quarantine/$(date +%s)
P=/home/user/bad.mp3

sha256sum -- "$P"                                   # record for your notes
mkdir -p "$Q$(dirname "$P")" && mv -- "$P" "$Q$P"   # quarantine
mv -- "$Q$P" "$P"                                   # restore
rm -f -- "$P"                                       # delete
```

Never remove top-level directories (`/home /root /tmp /var /opt /usr /etc`), a user's home directory, or `/opt/CyberPatriot*`. Media may be authorized by the README.

- [ ] Media, games, ROMs removed (unless allowed)
- [ ] Password lists and hash files gone
- [ ] Temp executables and backdoors gone
- [ ] Sensitive-text files handled

---

## 9. Pitfalls

1. README says it's required → **keep it** (package, service, user, port).
2. Don't lock yourself out: allow your SSH port, test faillock, run `sshd -t` before reloading, `visudo -c`.
3. Remove persistence before killing a process.
4. `login.defs` aging only affects new accounts; run `chage` for existing ones.
5. Simulate before purge; read the "extra packages" list.
6. Quarantine, don't delete, when unsure.
7. Re-check the Scoring Report; undo anything that cost points.

---

## Change Log

| Time | Area | Change | File / command | Before → After | Backup |
| ---- | ---- | ------ | -------------- | -------------- | ------ |
|      |      |        |                |                |        |
|      |      |        |                |                |        |
|      |      |        |                |                |        |
|      |      |        |                |                |        |
|      |      |        |                |                |        |
