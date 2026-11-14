#!/usr/bin/env bash
# harden.sh - keyboard-driven config hardening for CyberPatriot (Linux Mint 21)
# Pure bash + awk/diff/cmp. Run with: sudo ./harden.sh   (press ? inside for keybinds)
# Every change: diff -> confirm -> timestamped backup -> write -> log. Revert with u / b.
# HARDEN_ROOT=/some/dir prefixes every system path (sandbox testing, no root needed).

ROOT=${HARDEN_ROOT:-}
rp() { printf '%s%s' "$ROOT" "$1"; }

LOGFILE=$ROOT/var/log/cp-harden.log
USERLOG=$ROOT/var/log/usermgr.log
BKROOT=$ROOT/var/backups/cp-harden
MANI=$BKROOT/manifest.tsv

# ---------- glyphs ----------
if [[ ${LC_ALL:-${LC_CTYPE:-$LANG}} == *[Uu][Tt][Ff]* ]]; then
    HR='─' MK='●' KUD='↑↓' UP_ARR='↑' DN_ARR='↓' SEP='·' ARR='→'
else
    HR='-' MK='*' KUD='Up/Dn' UP_ARR='^' DN_ARR='v' SEP='|' ARR='->'
fi

# ---------- items ----------
# id|group|description|kind|file|key|op|want|default
# kinds: sshd kv defs ini pamopt flauth flacct sudoers autol      ops: eq le ge absent
ITEMS=(
"ssh-root|SSH|PermitRootLogin|sshd|/etc/ssh/sshd_config|PermitRootLogin|eq|no|prohibit-password"
"ssh-pass|SSH|PasswordAuthentication|sshd|/etc/ssh/sshd_config|PasswordAuthentication|eq|no|yes"
"ssh-empty|SSH|PermitEmptyPasswords|sshd|/etc/ssh/sshd_config|PermitEmptyPasswords|eq|no|no"
"ssh-x11|SSH|X11Forwarding|sshd|/etc/ssh/sshd_config|X11Forwarding|eq|no|no"
"ssh-tries|SSH|MaxAuthTries|sshd|/etc/ssh/sshd_config|MaxAuthTries|le|4|6"
"def-max|LOGIN|PASS_MAX_DAYS|defs|/etc/login.defs|PASS_MAX_DAYS|le|90|99999"
"def-min|LOGIN|PASS_MIN_DAYS|defs|/etc/login.defs|PASS_MIN_DAYS|ge|7|0"
"def-warn|LOGIN|PASS_WARN_AGE|defs|/etc/login.defs|PASS_WARN_AGE|ge|14|7"
"pam-minlen|PAM|password minlen|pamopt|/etc/pam.d/common-password|pam_pwquality.so,pam_unix.so:minlen|ge|10|"
"pam-remember|PAM|password history|pamopt|/etc/pam.d/common-password|pam_unix.so:remember|ge|5|"
"pam-nullok|PAM|nullok (blank pw login)|pamopt|/etc/pam.d/common-auth|pam_unix.so:nullok|absent||"
"pam-deny|PAM|faillock deny|kv|/etc/security/faillock.conf|deny|le|5|"
"pam-unlock|PAM|faillock unlock_time|kv|/etc/security/faillock.conf|unlock_time|ge|900|"
"pam-lock-auth|PAM|faillock in common-auth|flauth|/etc/pam.d/common-auth||||"
"pam-lock-acct|PAM|faillock in common-acct|flacct|/etc/pam.d/common-account||||"
"sys-fwd|SYSCTL|ip_forward|kv|/etc/sysctl.conf|net.ipv4.ip_forward|eq|0|"
"sys-syn|SYSCTL|tcp_syncookies|kv|/etc/sysctl.conf|net.ipv4.tcp_syncookies|eq|1|"
"sys-acc|SYSCTL|accept_redirects|kv|/etc/sysctl.conf|net.ipv4.conf.all.accept_redirects|eq|0|"
"sys-send|SYSCTL|send_redirects|kv|/etc/sysctl.conf|net.ipv4.conf.all.send_redirects|eq|0|"
"sys-rp|SYSCTL|rp_filter|kv|/etc/sysctl.conf|net.ipv4.conf.all.rp_filter|eq|1|"
"sys-aslr|SYSCTL|randomize_va_space|kv|/etc/sysctl.conf|kernel.randomize_va_space|eq|2|"
"ld-guest|LIGHTDM|allow-guest|ini|/etc/lightdm/lightdm.conf|Seat:*/allow-guest|eq|false|"
"ld-auto|LIGHTDM|autologin-user|autol|/etc/lightdm/lightdm.conf||||"
"sudoers|SUDOERS|NOPASSWD / odd grants|sudoers|/etc/sudoers||||"
)
I_ID=() I_GRP=() I_DESC=() I_KIND=() I_FILE=() I_KEY=() I_OP=() I_WANT=() I_DEF=()
I_ST=() I_CUR=() I_CHG=()
declare -A MARK=() POST=()

# ---------- state ----------
VIEW=() CUR=0 TOP=0 LH=10
ST="" SC=32 LASTERR="" ABORT=0 POSTNOTE=""
KEY="" PVAL="" PRES="" PG=() PGWARN="" MENU=() MSEL=-1
SAVED_STTY="" TMPD="" SEQ=0 REPORTED=0
J_ACT=() J_IDX=() J_LABEL=() J_PATH=() J_BK=() J_TS=() J_BEF=()
START_TS=$(date '+%F %T')

log() { printf '%s %s\n' "$(date '+%F %T')" "$*" >>"$LOGFILE" 2>/dev/null; }

# ---------- terminal ----------
init_term() { SAVED_STTY=$(stty -g); stty -echo; printf '\e[?1049h\e[?25l'; }
restore_term() {
    printf '\e[?25h\e[?1049l'
    [[ -n $SAVED_STTY ]] && stty "$SAVED_STTY" 2>/dev/null
}
get_size() {
    local r c
    read -r r c < <(stty size 2>/dev/null)
    LINES=${r:-24} COLUMNS=${c:-80}
    ((LINES < 10)) && LINES=10
    ((COLUMNS < 60)) && COLUMNS=60
}

# Sets KEY to: a single printable char, or UP DOWN LEFT RIGHT PGUP PGDN HOME END DEL ESC ENTER BS NONE
readkey() {
    local k k2 k3 rest
    IFS= read -rsn1 k
    local rc=$?
    if ((rc > 128)); then KEY=NONE; return; fi
    case $k in
        '')       KEY=ENTER ;;
        $'\x7f'|$'\b') KEY=BS ;;
        $'\e')
            if ! IFS= read -rsn1 -t 0.05 k2; then KEY=ESC; return; fi
            if [[ $k2 == '[' || $k2 == 'O' ]]; then
                IFS= read -rsn1 -t 0.05 k3
                case $k3 in
                    A) KEY=UP ;;   B) KEY=DOWN ;;
                    C) KEY=RIGHT ;; D) KEY=LEFT ;;
                    H) KEY=HOME ;; F) KEY=END ;;
                    [0-9])
                        IFS= read -rsn1 -t 0.05 rest
                        case $k3 in
                            1|7) KEY=HOME ;; 4|8) KEY=END ;;
                            5) KEY=PGUP ;;   6) KEY=PGDN ;;
                            3) KEY=DEL ;;    *) KEY=NONE ;;
                        esac ;;
                    *) KEY=NONE ;;
                esac
            else
                KEY=ESC
            fi ;;
        *) KEY=$k ;;
    esac
}

# ---------- file editors (all write the candidate to stdout) ----------
kv_get() {   # kv_get file key first|last  -> value of active "key value" / "key = value" line
    awk -v key="$2" -v mode="$3" '
        BEGIN { lk = tolower(key) }
        mode == "first" && tolower($1) == "match" { exit }
        /^[ \t]*[#;]/ { next }
        { t = $0; sub(/^[ \t]+/, "", t); k = t; sub(/[ \t=].*$/, "", k)
          if (tolower(k) == lk) { v = t; sub(/^[^ \t=]+[ \t]*=?[ \t]*/, "", v); sub(/[ \t]+$/, "", v)
              if (mode == "first") { print v; exit }
              val = v; f = 1 } }
        END { if (f) print val }' "$1"
}

kv_set() {   # kv_set file key value sshd|defs|eq
    awk -v key="$2" -v val="$3" -v style="$4" '
        function mk() { return style == "sshd" ? key " " val : style == "defs" ? key "\t" val : key " = " val }
        BEGIN { lk = tolower(key) }
        {
            line = $0
            if (style == "sshd" && !inm && line ~ /^[ \t]*[Mm][Aa][Tt][Cc][Hh][ \t]/) {
                if (!done) { print mk(); done = 1 }
                inm = 1; print line; next
            }
            if (!inm && line ~ /^[ \t]*[^# \t;]/) {
                t = line; sub(/^[ \t]+/, "", t); k = t; sub(/[ \t=].*$/, "", k)
                if (tolower(k) == lk) {
                    if (!done) { print mk(); done = 1 } else print "# cp-harden: " line
                    next
                }
            }
            print line
        }
        END { if (!done) print mk() }' "$1"
}

ini_get() {  # ini_get file section key -> last active value
    awk -v sec="$2" -v key="$3" '
        BEGIN { lk = tolower(key) }
        /^[ \t]*\[/ { s = $0; gsub(/^[ \t]*\[|\][ \t]*$/, "", s); ins = (s == sec); next }
        /^[ \t]*[#;]/ { next }
        ins && index($0, "=") { k = $0; sub(/=.*/, "", k); gsub(/[ \t]/, "", k)
            if (tolower(k) == lk) { v = $0; sub(/^[^=]*=[ \t]*/, "", v); sub(/[ \t]+$/, "", v); val = v; f = 1 } }
        END { if (f) print val }' "$1"
}

ini_set() {  # ini_set file section key value|__DEL__
    awk -v sec="$2" -v key="$3" -v val="$4" '
        function mk() { return key "=" val }
        function flush() { if (ins && !done && val != "__DEL__") { print mk(); done = 1 } }
        BEGIN { lk = tolower(key) }
        /^[ \t]*\[/ { flush(); s = $0; gsub(/^[ \t]*\[|\][ \t]*$/, "", s); ins = (s == sec); if (ins) seen = 1; print; next }
        ins && !/^[ \t]*[#;]/ && index($0, "=") {
            k = $0; sub(/=.*/, "", k); gsub(/[ \t]/, "", k)
            if (tolower(k) == lk) {
                if (val != "__DEL__" && !done) { print mk(); done = 1; next }
                print "# cp-harden: " $0; next
            }
        }
        { print }
        END { flush()
              if (!seen && val != "__DEL__") { if (NR > 0) print ""; print "[" sec "]"; print mk() } }' "$1"
}

pam_get() {  # pam_get file mod1,mod2 opt -> value | yes (flag) | "" (absent) | NOMOD
    awk -v mods="$2" -v opt="$3" '
        { L[NR] = $0 }
        END {
            n = split(mods, M, ",")
            for (i = 1; i <= n && c == ""; i++) for (j = 1; j <= NR; j++)
                if (L[j] !~ /^[ \t]*#/ && index(L[j], M[i])) { c = M[i]; break }
            if (c == "") { print "NOMOD"; exit }
            for (j = 1; j <= NR; j++) if (L[j] !~ /^[ \t]*#/ && index(L[j], c)) {
                m = split(L[j], T, /[ \t]+/)
                for (t = 1; t <= m; t++) {
                    if (T[t] == opt) { print "yes"; exit }
                    if (index(T[t], opt "=") == 1) { print substr(T[t], length(opt) + 2); exit }
                }
            }
        }' "$1"
}

pam_tok() {  # pam_tok file mod1,mod2 opt value|""(flag)|-(remove)
    awk -v mods="$2" -v opt="$3" -v val="$4" '
        { L[NR] = $0 }
        END {
            n = split(mods, M, ",")
            for (i = 1; i <= n && c == ""; i++) for (j = 1; j <= NR; j++)
                if (L[j] !~ /^[ \t]*#/ && index(L[j], M[i])) { c = M[i]; break }
            for (j = 1; j <= NR; j++) {
                l = L[j]
                if (c != "" && l !~ /^[ \t]*#/ && index(l, c)) {
                    l = l " "
                    while (match(l, "[ \t]" opt "(=[^ \t]*)?[ \t]")) l = substr(l, 1, RSTART - 1) " " substr(l, RSTART + RLENGTH)
                    sub(/[ \t]+$/, "", l)
                    if (val != "-") l = l " " opt (val != "" ? "=" val : "")
                }
                print l
            }
        }' "$1"
}

fl_auth() {  # wire pam_faillock around pam_unix in common-auth (skip count of pam_unix success=N gets +1)
    awk '
        !done && $0 !~ /^[ \t]*#/ && index($0, "pam_unix.so") {
            print "auth\trequired\t\t\tpam_faillock.so preauth"
            l = $0
            if (match(l, /success=[0-9]+/)) { nn = substr(l, RSTART + 8, RLENGTH - 8) + 1; l = substr(l, 1, RSTART + 7) nn substr(l, RSTART + RLENGTH) }
            print l
            print "auth\t[default=die]\t\t\tpam_faillock.so authfail"
            done = 1; next
        }
        { print }
        END { if (!done) { print "auth\trequired\t\t\tpam_faillock.so preauth"; print "auth\t[default=die]\t\t\tpam_faillock.so authfail" } }' "$1"
}

fl_acct() {  # account required pam_faillock.so before the first pam_unix account line
    awk '
        !done && $0 !~ /^[ \t]*#/ && index($0, "pam_unix.so") { print "account\trequired\t\t\tpam_faillock.so"; done = 1 }
        { print }
        END { if (!done) print "account\trequired\t\t\tpam_faillock.so" }' "$1"
}

sudo_findings() {  # file<TAB>line<TAB>text for risky active sudoers lines
    local f b
    for f in "$(rp /etc/sudoers)" "$(rp /etc/sudoers.d)"/*; do
        [[ -f $f ]] || continue
        b=${f##*/}
        [[ $f == */sudoers.d/* && ( $b == *.* || $b == *'~' ) ]] && continue
        awk -v F="$f" '
            /^[ \t]*$/ { next }
            /^[ \t]*#/ { next }
            /^[ \t]*(Defaults|User_Alias|Runas_Alias|Host_Alias|Cmnd_Alias)/ { if ($0 ~ /!authenticate/) print F "\t" NR "\t" $0; next }
            /NOPASSWD|!authenticate/ { print F "\t" NR "\t" $0; next }
            { t = $1; if (t != "root" && t != "%sudo" && t != "%admin" && $0 ~ /=.*ALL/) print F "\t" NR "\t" $0 }' "$f"
    done
}

ssh_eff() {  # sets EFFV EFFF: effective sshd value (drop-ins win, first match wins) and the file it lives in
    EFFV="" EFFF=$(rp /etc/ssh/sshd_config)
    local f v
    for f in "$(rp /etc/ssh/sshd_config.d)"/*.conf "$(rp /etc/ssh/sshd_config)"; do
        [[ -f $f ]] || continue
        v=$(kv_get "$f" "$1" first)
        if [[ -n $v ]]; then EFFV=$v EFFF=$f; return; fi
    done
}

ld_files() { local f; for f in "$(rp /etc/lightdm/lightdm.conf.d)"/*.conf "$(rp /etc/lightdm/lightdm.conf)"; do [[ -f $f ]] && printf '%s\n' "$f"; done; }

# ---------- checks ----------
cmp_ok() {  # op cur want
    case $1 in
        eq)     [[ ${2,,} == "${3,,}" ]] ;;
        le)     [[ $2 =~ ^[0-9]+$ ]] && ((10#$2 <= 10#$3)) ;;
        ge)     [[ $2 =~ ^[0-9]+$ ]] && ((10#$2 >= 10#$3)) ;;
        absent) [[ -z $2 ]] ;;
    esac
}

wtxt() {
    local i=$1
    case ${I_KIND[i]} in
        flauth|flacct) echo present; return ;;
        sudoers|autol) echo none; return ;;
    esac
    case ${I_OP[i]} in
        le) echo "<=${I_WANT[i]}" ;; ge) echo ">=${I_WANT[i]}" ;;
        absent) echo removed ;;     *) echo "${I_WANT[i]}" ;;
    esac
}

scan_item() {
    local i=$1 kind=${I_KIND[i]} key=${I_KEY[i]} def=${I_DEF[i]} f cur="" cmpv="" st=FIX v x
    f=$(rp "${I_FILE[i]}")
    case $kind in
        sshd)
            if [[ ! -f $f ]]; then st=NA cur="no sshd_config"
            else ssh_eff "$key"; v=$EFFV; cmpv=${v:-$def}; cur=${v:-"$def (default)"}; fi ;;
        kv|defs)
            if [[ ! -d ${f%/*} ]]; then st=NA cur="missing dir"
            else
                v=""; [[ -f $f ]] && v=$(kv_get "$f" "$key" last)
                cmpv=${v:-$def}; cur=${v:-${def:+$def (default)}}; cur=${cur:-(unset)}
            fi ;;
        ini)
            if [[ ! -d $(rp /etc/lightdm) ]]; then st=NA cur="lightdm not installed"
            else
                v=""
                while IFS= read -r x; do
                    x=$(ini_get "$x" "${key%%/*}" "${key#*/}"); [[ -n $x ]] && v=$x
                done < <(ld_files)
                cmpv=$v; cur=${v:-(unset)}
            fi ;;
        pamopt)
            if [[ ! -f $f ]]; then st=NA cur="missing file"
            else
                v=$(pam_get "$f" "${key%%:*}" "${key##*:}")
                if [[ $v == NOMOD ]]; then st=NA cur="module not found"
                else cmpv=$v; cur=${v:-(none)}; fi
            fi ;;
        flauth|flacct)
            if [[ ! -f $f ]]; then st=NA cur="missing file"
            elif [[ -z $ROOT ]] && ! ls /lib/*/security/pam_faillock.so /usr/lib/*/security/pam_faillock.so >/dev/null 2>&1; then st=NA cur="pam_faillock.so absent"
            elif grep -Eq '^[^#]*pam_faillock\.so' "$f"; then st=ok cur=present
            else cur=missing; fi ;;
        sudoers)
            local n; n=$(sudo_findings | wc -l)
            cur="$n finding(s)"; ((n == 0)) && st=ok || st=WARN ;;
        autol)
            if [[ ! -d $(rp /etc/lightdm) ]]; then st=NA cur="lightdm not installed"
            else
                v=""
                while IFS= read -r x; do
                    x=$(ini_get "$x" 'Seat:*' autologin-user); [[ -n $x ]] && v+="$x "
                done < <(ld_files)
                cur=${v:-none}; [[ -z $v ]] && st=ok
            fi ;;
    esac
    case $kind in sshd|kv|defs|ini|pamopt) [[ $st == FIX ]] && cmp_ok "${I_OP[i]}" "$cmpv" "${I_WANT[i]}" && st=ok ;; esac
    [[ $st != ok ]] && I_CHG[i]=0
    I_ST[i]=$st I_CUR[i]=${cur% }
}

scan_all() { local i; for i in "${!I_ID[@]}"; do scan_item "$i"; done; }

load_items() {
    local row n=0
    for row in "${ITEMS[@]}"; do
        IFS='|' read -r I_ID[n] I_GRP[n] I_DESC[n] I_KIND[n] I_FILE[n] I_KEY[n] I_OP[n] I_WANT[n] I_DEF[n] <<<"$row"
        I_CHG[n]=0; ((n++))
    done
}

item_warn() {
    case ${I_KIND[$1]} in
        flauth|flacct) echo "Lockout misconfig can lock EVERY account out - keep a root shell open and test login before closing it." ;;
        sudoers)       echo "Commenting out a sudo rule: check the README first, it may be required." ;;
        sshd)          [[ ${I_KEY[$1]} == PasswordAuthentication ]] && echo "Check the README: some rounds require password SSH." ;;
    esac
}

# ---------- pager / menu / prompts ----------
# pager "title" confirm|view   -- lines in PG[], optional PGWARN. Sets PRES: y n q (confirm) / q (view)
pager() {
    local title=$1 mode=$2 top=0 n=${#PG[@]} W H i l buf sp foot max
    while :; do
        get_size; W=$COLUMNS; H=$((LINES - 3))
        max=$((n - H)); ((max < 0)) && max=0
        ((top > max)) && top=$max; ((top < 0)) && top=0
        printf -v sp '%*s' $((W - ${#title} - 1 > 0 ? W - ${#title} - 1 : 1)) ''
        buf=$'\e[H\e[1;97;44m '"${title:0:W-1}${sp}"$'\e[0m\e[K\n'
        buf+=$'\e[1;91m '"${PGWARN:0:W-2}"$'\e[0m\e[K\n'
        for ((i = 0; i < H; i++)); do
            if ((top + i < n)); then
                l=${PG[top + i]//$'\t'/    }; l=${l:0:W}
                case $l in
                    '+++'*|'---'*) buf+=$'\e[1m'"$l" ;;
                    '+'*)  buf+=$'\e[32m'"$l" ;;
                    '-'*)  buf+=$'\e[31m'"$l" ;;
                    '@@'*) buf+=$'\e[36m'"$l" ;;
                    *)     buf+="$l" ;;
                esac
                buf+=$'\e[0m\e[K\n'
            else buf+=$'\e[K\n'; fi
        done
        if [[ $mode == confirm ]]; then foot=" \e[1;32my\e[0m\e[90m apply  \e[1;33mn\e[0m\e[90m skip  \e[1;31mq\e[0m\e[90m abort all  \e[1;36m$KUD\e[0m\e[90m scroll"
        else foot=" \e[1;36mq/Esc\e[0m\e[90m close  \e[1;36m$KUD PgUp PgDn g G\e[0m\e[90m scroll"; fi
        buf+="$(printf '%b' "$foot")"$'\e[0m\e[90m  '"$((n ? top + 1 : 0))-$((top + H < n ? top + H : n))/$n"$'\e[0m\e[K\e[J'
        printf '%s' "$buf"
        readkey
        case $KEY in
            UP|k)   ((top > 0)) && ((top--)) ;;
            DOWN|j) ((top < max)) && ((top++)) ;;
            PGUP)   top=$((top - H + 1)) ;;
            PGDN|' ') top=$((top + H - 1)) ;;
            HOME|g) top=0 ;;
            END|G)  top=$max ;;
            y|Y)    [[ $mode == confirm ]] && { PRES=y; return; } ;;
            n|N)    [[ $mode == confirm ]] && { PRES=n; return; } ;;
            ESC)    if [[ $mode == confirm ]]; then PRES=n; else PRES=q; fi; return ;;
            q|Q)    PRES=q; return ;;
        esac
    done
}

# menu "title" -- lines in MENU[]; sets MSEL (index or -1)
menu() {
    local title=$1 cur=0 top=0 n=${#MENU[@]} W H i l buf sp
    while :; do
        get_size; W=$COLUMNS; H=$((LINES - 3))
        ((cur >= top + H)) && top=$((cur - H + 1)); ((cur < top)) && top=$cur
        printf -v sp '%*s' $((W - ${#title} - 1 > 0 ? W - ${#title} - 1 : 1)) ''
        buf=$'\e[H\e[1;97;44m '"${title:0:W-1}${sp}"$'\e[0m\e[K\n\e[K\n'
        for ((i = 0; i < H; i++)); do
            if ((top + i < n)); then
                l=${MENU[top + i]:0:W-2}
                if ((top + i == cur)); then buf+=$'\e[48;5;24m\e[97m'" $l"$'\e[0m\e[K\n'; else buf+=" $l"$'\e[K\n'; fi
            else buf+=$'\e[K\n'; fi
        done
        buf+=$'\e[1;36m Enter\e[0m\e[90m select  \e[1;36m'"$KUD"$'\e[0m\e[90m move  \e[1;36mq/Esc\e[0m\e[90m cancel\e[0m\e[K\e[J'
        printf '%s' "$buf"
        readkey
        case $KEY in
            UP|k)   ((cur > 0)) && ((cur--)) ;;
            DOWN|j) ((cur < n - 1)) && ((cur++)) ;;
            PGUP)   cur=$((cur - H + 1)); ((cur < 0)) && cur=0 ;;
            PGDN)   cur=$((cur + H - 1)); ((cur > n - 1)) && cur=$((n - 1)) ;;
            HOME|g) cur=0 ;;
            END|G)  cur=$((n - 1)) ;;
            ENTER)  MSEL=$cur; return ;;
            ESC|q|Q) MSEL=-1; return ;;
        esac
    done
}

prompt() {   # prompt "label" [secret] [initial] -> PVAL ; returns 1 on Esc
    local label=$1 secret=${2:-0} s=${3:-} disp
    printf '\e[?25h'
    while :; do
        disp=$s; ((secret)) && disp=${s//?/*}
        printf '\e[%d;1H\e[K\e[1;36m %s\e[0m %s' "$LINES" "$label" "${disp: -$((COLUMNS - ${#label} - 4))}"
        readkey
        case $KEY in
            ENTER) break ;;
            ESC) printf '\e[?25l'; return 1 ;;
            BS) s=${s%?} ;;
            ?) s+=$KEY ;;
        esac
    done
    printf '\e[?25l'
    PVAL=$s
}

confirm() {  # confirm "question" [default y|n]
    local def=${2:-n} hint='[y/N]'
    [[ $def == y ]] && hint='[Y/n]'
    printf '\e[%d;1H\e[K\e[1;33m %s %s\e[0m' "$LINES" "${1:0:COLUMNS-10}" "$hint"
    while :; do
        readkey
        case $KEY in
            y|Y) return 0 ;;
            n|N|ESC) return 1 ;;
            ENTER) [[ $def == y ]]; return ;;
        esac
    done
}

# ---------- journal / backup / apply ----------
jrec() {  # jrec ACT idx label path backup   (diff taken from PG)
    local n=${#J_ACT[@]}
    J_ACT+=("$1") J_IDX+=("$2") J_LABEL+=("$3") J_PATH+=("$4") J_BK+=("$5") J_TS+=("$(date '+%T')")
    if (($2 >= 0)); then J_BEF+=("${I_CUR[$2]}"); else J_BEF+=(""); fi
    [[ $1 == APPLY || $1 == REVERT ]] && printf '%s\n' "${PG[@]}" >"$TMPD/j$n.diff"
}

post_for() {
    case $1 in
        */sshd_config|*/sshd_config.d/*) echo "systemctl reload ssh" ;;
        */sysctl.conf)                  echo "sysctl -p /etc/sysctl.conf" ;;
    esac
}
queue_post() {
    local c; c=$(post_for "$1")
    if [[ -n $c ]]; then POST[$c]=1; elif [[ $1 == */lightdm* ]]; then POSTNOTE=" (LightDM: takes effect at next login screen)"; fi
}
run_posts() {
    local c
    for c in "${!POST[@]}"; do
        if [[ -n $ROOT ]]; then log "SANDBOX would run: $c"; continue; fi
        if confirm "Run '$c' now?" y; then
            local o rc; o=$($c 2>&1); rc=$?
            if ((rc)); then log "FAIL($rc) $c: ${o//$'\n'/ }"; ST="'$c' failed: ${o:0:60}"; SC=31
            else log "OK   $c"; fi
        fi
    done
    POST=()
}

validate() {  # validate kind cand -> 0 ok / 1 bad (VMSG)
    VMSG=""
    case $1 in
        sshd)    local s; s=$(command -v sshd || echo /usr/sbin/sshd)
                 [[ -x $s ]] && ! VMSG=$("$s" -t -f "$2" 2>&1) && { VMSG=${VMSG//$'\n'/ }; return 1; } ;;
        sudoers) command -v visudo >/dev/null && ! VMSG=$(visudo -cf "$2" 2>&1) && { VMSG=${VMSG//$'\n'/ }; return 1; } ;;
    esac
    return 0
}

show_diff() {  # show_diff title tgt old new  -> PRES
    PG=(); local l t=${2#"$ROOT"} lab="$2 (current)"
    [[ $3 == /dev/null ]] && lab="$t (does not exist)"
    while IFS= read -r l; do PG+=("$l"); done < <(diff -u --label "$lab" --label "$t (proposed)" "$3" "$4")
    pager "$1" confirm
}

# apply_change idx label tgt cand [validator] -> 0 applied, 1 skipped/failed, 2 no change
apply_change() {
    local i=$1 label=$2 tgt=$3 cand=$4 vk=${5:-} old=$3 existed=1 bk dir
    [[ -f $tgt ]] || { old=/dev/null; existed=0; }
    cmp -s "$old" "$cand" && return 2
    PGWARN=$( ((i >= 0)) && item_warn "$i" )
    show_diff "Change: $label  ${tgt#"$ROOT"}" "$tgt" "$old" "$cand"
    PGWARN=""
    case $PRES in
        q) ABORT=1; log "SKIP $label (abort)"; jrec SKIP "$i" "$label" "$tgt" ""; return 1 ;;
        n) log "SKIP $label"; jrec SKIP "$i" "$label" "$tgt" ""; return 1 ;;
    esac
    if ! validate "$vk" "$cand"; then
        confirm "Validation FAILED: ${VMSG:0:55} Apply anyway?" n || { log "FAIL validate $label: $VMSG"; LASTERR="validation: $VMSG"; return 1; }
    fi
    dir=$BKROOT/$(date +%Y%m%d-%H%M%S)-$$-$((++SEQ))
    bk=$dir/${tgt#/}
    if ((existed)); then
        mkdir -p "${bk%/*}" && cp -a "$tgt" "$bk" || { LASTERR="backup failed"; log "FAIL backup $tgt"; return 1; }
    fi
    mkdir -p "${tgt%/*}"
    if ! cat "$cand" >"$tgt" 2>/dev/null; then LASTERR="write failed: $tgt"; log "FAIL write $tgt"; return 1; fi
    printf 'APPLY\t%s\t%s\t%s\t%s\t%s\n' "$(date '+%F %T')" "$label" "$tgt" "$bk" "$existed" >>"$MANI"
    log "APPLY $label -> $tgt (backup: $bk)"
    jrec APPLY "$i" "$label" "$tgt" "$bk"
    ((i >= 0)) && I_CHG[i]=1
    queue_post "$tgt"
    return 0
}

make_cand() {  # make_cand idx src dst
    local i=$1 s=$2 dst=$3 key=${I_KEY[i]} want=${I_WANT[i]} v
    [[ -f $s ]] || s=/dev/null
    case ${I_KIND[i]} in
        sshd)   kv_set "$s" "$key" "$want" sshd >"$dst" ;;
        defs)   kv_set "$s" "$key" "$want" defs >"$dst" ;;
        kv)     kv_set "$s" "$key" "$want" eq >"$dst" ;;
        ini)    ini_set "$s" "${key%%/*}" "${key#*/}" "$want" >"$dst" ;;
        pamopt) v=$want; [[ ${I_OP[i]} == absent ]] && v=-
                pam_tok "$s" "${key%%:*}" "${key##*:}" "$v" >"$dst" ;;
        flauth) fl_auth "$s" >"$dst" ;;
        flacct) fl_acct "$s" >"$dst" ;;
    esac
}

fix_item() {
    local i=$1 tgt cand n=0 sf sn st ld
    case ${I_KIND[i]} in
        sudoers)
            while IFS=$'\t' read -r sf sn st; do
                cand=$TMPD/cand.$$; awk -v n="$sn" 'NR == n { print "# cp-harden: " $0; next } 1' "$sf" >"$cand"
                apply_change "$i" "sudoers: ${sf##*/}:$sn" "$sf" "$cand" sudoers && ((APPLIED++)) || ((SKIPPED++))
                ((ABORT)) && break
            done < <(sudo_findings)
            return ;;
        autol)
            while IFS= read -r ld; do
                [[ -n $(ini_get "$ld" 'Seat:*' autologin-user) ]] || continue
                cand=$TMPD/cand.$$; ini_set "$ld" 'Seat:*' autologin-user __DEL__ >"$cand"
                apply_change "$i" "${I_DESC[i]}: ${ld##*/}" "$ld" "$cand" && ((APPLIED++)) || ((SKIPPED++))
                ((ABORT)) && break
            done < <(ld_files)
            return ;;
        sshd) ssh_eff "${I_KEY[i]}"; tgt=$EFFF ;;
        ini)  tgt=$(rp /etc/lightdm/lightdm.conf) ;;
        *)    tgt=$(rp "${I_FILE[i]}") ;;
    esac
    cand=$TMPD/cand.$$
    make_cand "$i" "$tgt" "$cand"
    apply_change "$i" "${I_DESC[i]}" "$tgt" "$cand" "$([[ ${I_KIND[i]} == sshd ]] && echo sshd)"
    case $? in 0) ((APPLIED++)) ;; 1) ((SKIPPED++)) ;; esac
}

# ---------- revert ----------
pending() {  # newest-first APPLY manifest lines that have not been reverted
    [[ -f $MANI ]] || return
    awk -F'\t' '$1 == "APPLY" { a[NR] = $0; b[NR] = $5; n = NR } $1 == "REVERT" { r[$5] = 1 }
        END { for (i = n; i >= 1; i--) if ((i in a) && !(b[i] in r)) print a[i] }' "$MANI"
}

revert_entry() {  # one manifest line
    local act ts label path bk existed old new l
    IFS=$'\t' read -r act ts label path bk existed <<<"$1"
    old=$path; [[ -f $path ]] || old=/dev/null
    if ((existed)); then
        [[ -f $bk ]] || { ST="Backup file missing: $bk"; SC=31; return 1; }
        new=$bk
    else new=/dev/null; fi
    if cmp -s "$old" "$new"; then ST="'$label' already matches its backup"; SC=33; return 1; fi
    PG=(); PGWARN="Restores the file as it was before the change at $ts"
    ((existed)) || PGWARN+=" (file will be deleted)"
    while IFS= read -r l; do PG+=("$l"); done < <(diff -u --label "${path#"$ROOT"} (current)" --label "${path#"$ROOT"} (backup $ts)" "$old" "$new")
    pager "Revert: $label" confirm; PGWARN=""
    if [[ $PRES != y ]]; then ST="Revert cancelled"; SC=33; return 1; fi
    if ((existed)); then cat "$bk" >"$path" || { ST="Restore failed"; SC=31; return 1; }
    else rm -f "$path"; fi
    printf 'REVERT\t%s\t%s\t%s\t%s\t%s\n' "$(date '+%F %T')" "$label" "$path" "$bk" "$existed" >>"$MANI"
    log "REVERT $label -> $path (from $bk)"
    jrec REVERT -1 "$label" "$path" "$bk"
    queue_post "$path"
    ST="Reverted: $label"; SC=32
}

act_undo() {
    local line; line=$(pending | head -n1)
    [[ -z $line ]] && { ST="Nothing to revert"; SC=33; return; }
    revert_entry "$line" && { scan_all; run_posts; }
}

act_backups() {
    MENU=(); local -a L=(); local line act ts label path bk ex
    while IFS= read -r line; do
        IFS=$'\t' read -r act ts label path bk ex <<<"$line"
        L+=("$line"); MENU+=("$(printf '%-19s  %-28.28s  %s' "$ts" "$label" "${path#"$ROOT"}")")
    done < <(pending)
    ((${#L[@]})) || { ST="No unreverted backups"; SC=33; return; }
    menu "Backups - Enter to review revert"
    ((MSEL >= 0)) && revert_entry "${L[MSEL]}" && { scan_all; run_posts; }
}

# ---------- views ----------
view_file() {  # view_file path title
    if [[ ! -f $1 ]]; then ST="No such file: ${1#"$ROOT"}"; SC=33; return; fi
    PG=(); local l; while IFS= read -r l; do PG+=("$l"); done < <(tail -n 2000 "$1")
    PGWARN=""; pager "$2" view
}

act_view() {
    local i=${VIEW[CUR]} f
    case ${I_KIND[i]} in sshd) ssh_eff "${I_KEY[i]}"; f=$EFFF ;; *) f=$(rp "${I_FILE[i]}") ;; esac
    view_file "$f" "${f#"$ROOT"}"
}

# ---------- report ----------
act_report() {
    local def dir home n i a
    home=$HOME
    [[ -n $SUDO_USER ]] && home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    def=${home:-/root}/cp-report-$(date +%Y%m%d-%H%M).md
    prompt "Save report to:" 0 "$def" || { ST="Cancelled"; SC=33; return; }
    local out=$PVAL
    [[ -z $out ]] && return
    if [[ -e $out ]]; then confirm "'$out' exists. Overwrite?" n || { ST="Cancelled"; SC=33; return; }
    else confirm "Write report to $out?" y || { ST="Cancelled"; SC=33; return; }; fi
    scan_all
    {
        echo "# CyberPatriot Hardening Report"
        echo
        echo "- **Host:** $(hostname)"
        echo "- **OS:** $(. "$(rp /etc/os-release)" 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"
        echo "- **Operator:** ${SUDO_USER:-root}"
        echo "- **Session:** $START_TS - $(date '+%F %T')"
        echo
        echo "## Summary"
        echo
        n=${#J_ACT[@]}
        if ((n == 0)); then echo "_No changes were made this session._"; else
            echo "| # | Time | Action | Item | File | Before -> After |"
            echo "|---|------|--------|------|------|-----------------|"
            for ((i = 0; i < n; i++)); do
                a=""; ((J_IDX[i] >= 0)) && [[ ${J_ACT[i]} == APPLY ]] && a="${J_BEF[i]} -> ${I_CUR[J_IDX[i]]}"
                printf '| %d | %s | %s | %s | `%s` | %s |\n' "$((i + 1))" "${J_TS[i]}" "${J_ACT[i]}" "${J_LABEL[i]//|/\\|}" "${J_PATH[i]#"$ROOT"}" "${a//|/\\|}"
            done
        fi
        echo
        echo "## Changes"
        for ((i = 0; i < n; i++)); do
            [[ ${J_ACT[i]} == SKIP ]] && continue
            echo
            echo "### $((i + 1)). ${J_ACT[i]}: ${J_LABEL[i]}"
            echo
            echo "- File: \`${J_PATH[i]#"$ROOT"}\`"
            echo "- Time: ${J_TS[i]}"
            [[ -n ${J_BK[i]} ]] && echo "- Backup: \`${J_BK[i]#"$ROOT"}\`"
            echo
            echo '```diff'; cat "$TMPD/j$i.diff" 2>/dev/null; echo '```'
        done
        echo
        echo "## Reviewed but skipped"
        echo
        a=0; for ((i = 0; i < n; i++)); do [[ ${J_ACT[i]} == SKIP ]] && { echo "- ${J_LABEL[i]} (\`${J_PATH[i]#"$ROOT"}\`)"; a=1; }; done
        ((a)) || echo "_None._"
        echo
        echo "## Current state"
        echo
        echo "| Group | Check | Status | Current | Target |"
        echo "|-------|-------|--------|---------|--------|"
        for i in "${!I_ID[@]}"; do
            printf '| %s | %s | %s | %s | %s |\n' "${I_GRP[i]}" "${I_DESC[i]}" "${I_ST[i]}$( ((I_CHG[i])) && echo ' (changed)')" "${I_CUR[i]//|/\\|}" "$(wtxt "$i")"
        done
        echo
        echo "_Existing accounts keep their old password aging; apply with \`chage\` if PASS_* values were changed._"
        if [[ -f $USERLOG ]]; then
            echo
            echo "## Appendix: user management log (this session)"
            echo
            echo '```'; awk -v s="$START_TS" '($1 " " $2) >= s' "$USERLOG"; echo '```'
        fi
        echo
        echo "## Appendix: hardening log (this session)"
        echo
        echo '```'; awk -v s="$START_TS" '($1 " " $2) >= s' "$LOGFILE"; echo '```'
    } >"$out" 2>/dev/null || { ST="Could not write $out"; SC=31; return; }
    [[ -n $SUDO_USER ]] && chown "$SUDO_USER": "$out" 2>/dev/null
    REPORTED=1; log "REPORT written to $out"
    ST="Report saved: $out"; SC=32
}

# ---------- actions ----------
act_fix() {
    local t=() i
    for i in "${VIEW[@]}"; do [[ -n ${MARK[$i]} ]] && t+=("$i"); done
    ((${#t[@]})) || t=("${VIEW[CUR]}")
    ABORT=0 APPLIED=0 SKIPPED=0 POSTNOTE="" LASTERR=""
    local fixed_any=0
    for i in "${t[@]}"; do
        case ${I_ST[i]} in
            ok) continue ;;
            NA) ST="${I_DESC[i]}: not applicable (${I_CUR[i]})"; SC=33; continue ;;
        esac
        fix_item "$i"
        unset 'MARK[$i]'
        ((ABORT)) && break
    done
    scan_all; run_posts
    if [[ -n $LASTERR ]]; then ST="Failed: $LASTERR"; SC=31
    elif ((APPLIED + SKIPPED == 0)); then [[ $SC == 33 ]] || { ST="Nothing to change"; SC=36; }
    else ST="Applied $APPLIED, skipped $SKIPPED$POSTNOTE"; SC=32; fi
    ((ABORT)) && { ST="Aborted. $ST"; SC=33; }
}

# ---------- drawing ----------
clamp() {
    local n=${#VIEW[@]}
    ((CUR >= n)) && CUR=$((n - 1))
    ((CUR < 0)) && CUR=0
    ((CUR < TOP)) && TOP=$CUR
    ((CUR >= TOP + LH)) && TOP=$((CUR - LH + 1))
    ((TOP < 0)) && TOP=0
}

draw() {
    local W=$COLUMNS i row idx buf nu=${#VIEW[@]} nfix=0 nchg=0
    LH=$((LINES - 5)); ((LH < 1)) && LH=1
    clamp
    for i in "${VIEW[@]}"; do
        [[ ${I_ST[i]} == FIX || ${I_ST[i]} == WARN ]] && ((nfix++))
        ((I_CHG[i])) && ((nchg++))
    done
    local left=" CyberPatriot Hardening" right sp
    right="$nu checks $SEP $nfix to fix $SEP $nchg changed "
    printf -v sp '%*s' $((W - ${#left} - ${#right} > 0 ? W - ${#left} - ${#right} : 1)) ''
    buf=$'\e[H\e[1;97;44m'"${left}${sp}${right}"$'\e[0m\e[K\n'
    local hdr
    printf -v hdr ' %-2s%-8s%-26s %-8s %s' '' GROUP CHECK STATUS "CURRENT $ARR TARGET"
    buf+=$'\e[1;36m'"${hdr:0:W}"$'\e[0m\e[K\n'

    local tailw=$((W - 47)); ((tailw < 0)) && tailw=0
    for ((row = 0; row < LH; row++)); do
        idx=$((TOP + row))
        if ((idx >= nu)); then buf+=$'\e[K\n'; continue; fi
        i=${VIEW[idx]}
        local base=$'\e[39m' pre=""
        ((idx == CUR)) && { pre=$'\e[48;5;24m\e[97m'; base=$'\e[97m'; }
        local mk=" "; [[ -n ${MARK[$i]} ]] && mk="$MK"
        local stt=${I_ST[i]} stc=$'\e[33m'
        case $stt in
            ok)   stc=$'\e[32m'; ((I_CHG[i])) && { stt=changed; stc=$'\e[1;36m'; } ;;
            WARN) stc=$'\e[1;91m' ;;
            NA)   stt="n/a"; stc=$'\e[90m' ;;
        esac
        local tail="${I_CUR[i]} $ARR $(wtxt "$i")" part line
        [[ ${I_ST[i]} == ok ]] && tail="${I_CUR[i]}"
        line="$pre "
        [[ -n ${MARK[$i]} ]] && line+=$'\e[92m'
        printf -v part '%s  ' "$mk"; line+="$part$base"
        printf -v part '%-7s ' "${I_GRP[i]}"; line+="$part"
        printf -v part '%-26.26s ' "${I_DESC[i]}"; line+="$part"
        printf -v part '%-8s ' "$stt"; line+="$stc$part$base"
        printf -v part '%-*.*s' "$tailw" "$tailw" "$tail"; line+="$part"
        buf+="$line"$'\e[0m\e[K\n'
    done

    local info=""
    ((TOP > 0)) && info+=" $UP_ARR more "
    ((TOP + LH < nu)) && info+=" $DN_ARR more "
    local rule; printf -v rule '%*s' $((W - ${#info})) ''
    buf+=$'\e[2m'"${rule// /$HR}${info}"$'\e[0m\e[K\n'
    buf+=$'\e['"$SC"'m '"${ST:0:W-2}"$'\e[0m\e[K\n'

    local -a hints=("$KUD:move" "Space:mark" "Enter:fix" "a:all" "v:view" "u:undo" "b:backups" "R:report" "L:log" "?:help" "q:quit")
    local h used=1 kline=" "
    for h in "${hints[@]}"; do
        local kk=${h%%:*} ll=${h#*:}
        ((used + ${#kk} + ${#ll} + 3 > W)) && break
        kline+=$'\e[1;36m'"$kk"$'\e[0m\e[90m'" $ll  "$'\e[0m'
        ((used += ${#kk} + ${#ll} + 3))
    done
    buf+="$kline"$'\e[K\e[J'
    printf '%s' "$buf"
}

show_help() {
    PG=(
        "  Up/Down  j/k       move                PgUp/PgDn  Home/End  g/G   jump"
        "  Space              mark / unmark       a  mark all needing fix    A  clear marks"
        "  Enter  f           fix highlighted item (or every marked item)"
        "                     -> shows a diff, nothing is written until you press y"
        "  v                  view the target file"
        "  u                  undo (revert) the most recent change"
        "  b                  backup browser: pick any change to revert"
        "  R                  write post-round report (Markdown)"
        "  L                  view this tool's log"
        "  r                  rescan            q  quit"
        ""
        "STATUS   ok = compliant   FIX = will change   WARN = sudoers finding"
        "         changed = fixed this session   n/a = file/module missing"
        ""
        "Backups : ${BKROOT#"$ROOT"}/<timestamp>/<original path>   (manifest.tsv)"
        "Log     : ${LOGFILE#"$ROOT"}"
        "Diff pager: y apply   n skip   q abort the rest"
        "PAM lockout can lock everyone out - keep a root shell open and test."
    )
    PGWARN=""; pager "Help" view
}

# ---------- main ----------
main_loop() {
    local n k i
    while :; do
        get_size
        n=${#VIEW[@]}
        draw
        readkey
        ST=""; SC=32
        case $KEY in
            UP|k)   ((CUR > 0)) && ((CUR--)) ;;
            DOWN|j) ((CUR < n - 1)) && ((CUR++)) ;;
            PGUP)   CUR=$((CUR - LH + 1)); ((CUR < 0)) && CUR=0 ;;
            PGDN)   CUR=$((CUR + LH - 1)); ((CUR > n - 1)) && CUR=$((n - 1)) ;;
            HOME|g) CUR=0 ;;
            END|G)  CUR=$((n - 1)) ;;
            ' ')    i=${VIEW[CUR]}
                    if [[ -n ${MARK[$i]} ]]; then unset 'MARK[$i]'; else MARK[$i]=1; fi
                    ((CUR < n - 1)) && ((CUR++)) ;;
            a)      for i in "${VIEW[@]}"; do [[ ${I_ST[i]} == FIX || ${I_ST[i]} == WARN ]] && MARK[$i]=1; done ;;
            A)      MARK=() ;;
            ENTER|f) act_fix ;;
            v)      act_view ;;
            u)      act_undo ;;
            b)      act_backups ;;
            R)      act_report ;;
            L)      view_file "$LOGFILE" "Log: ${LOGFILE#"$ROOT"}" ;;
            r)      scan_all; ST="Rescanned"; SC=36 ;;
            '?'|h)  show_help ;;
            q|Q)    if ((${#J_ACT[@]} && !REPORTED)) && confirm "Save a post-round report before quitting?" y; then act_report; fi
                    return ;;
        esac
        clamp
    done
}

main() {
    if [[ -z $ROOT && $EUID -ne 0 ]]; then
        if command -v sudo >/dev/null; then
            echo "harden: needs root, re-running with sudo..." >&2
            exec sudo bash "$(readlink -f "$0")" "$@"
        fi
        echo "harden: must be run as root (try: sudo $0)" >&2; exit 1
    fi
    if [[ ! -t 0 || ! -t 1 ]]; then echo "harden: needs an interactive terminal" >&2; exit 1; fi
    local c
    for c in awk diff cmp mktemp stty sort date cp tail; do
        command -v "$c" >/dev/null || { echo "harden: missing command: $c" >&2; exit 1; }
    done
    mkdir -p "${LOGFILE%/*}" "$BKROOT" 2>/dev/null; chmod 700 "$BKROOT" 2>/dev/null
    touch "$LOGFILE" "$MANI" 2>/dev/null; chmod 600 "$LOGFILE" "$MANI" 2>/dev/null
    TMPD=$(mktemp -d) || exit 1
    trap 'restore_term; rm -rf "$TMPD"; exit 0' EXIT
    trap 'exit 130' INT TERM
    trap ':' WINCH
    load_items
    init_term
    get_size
    scan_all
    local i; for i in "${!I_ID[@]}"; do VIEW+=("$i"); done
    log "session start (invoked by ${SUDO_USER:-root})"
    main_loop
    log "session end"
}

[[ ${BASH_SOURCE[0]} == "$0" ]] && main "$@"
