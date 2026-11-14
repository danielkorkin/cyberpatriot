#!/usr/bin/env bash
# procwatch.sh - keyboard-driven process & persistence triage for CyberPatriot (Linux Mint 21)
# Pure bash + ps/ss/find/grep/systemctl/crontab. Run with: sudo ./procwatch.sh
# Press ? inside for keybinds. R writes a Markdown post-round report.
# Scans are read-only. Every kill / stop / disable asks first and is logged.

LOGFILE=/var/log/procwatch.log
BAKROOT=/root/procwatch-backup
BAKDIR=$BAKROOT/$(date +%Y%m%d-%H%M%S)
ALLOWF=/root/procwatch-allow.txt

if [[ $EUID -ne 0 ]]; then
    echo "procwatch: must be run as root (try: sudo $0)" >&2
    exit 1
fi
if [[ ! -t 0 || ! -t 1 ]]; then
    echo "procwatch: needs an interactive terminal" >&2
    exit 1
fi
for c in ps ss find grep sort stat sha256sum less mktemp stty sed getent crontab systemctl readlink tr; do
    command -v "$c" >/dev/null || { echo "procwatch: missing command: $c" >&2; exit 1; }
done

# ---------- glyphs ----------
if [[ ${LC_ALL:-${LC_CTYPE:-$LANG}} == *[Uu][Tt][Ff]* ]]; then
    HR='─' MK='●' KUD='↑↓' UP_ARR='↑' DN_ARR='↓' SEP='·' ELL='…'
else
    HR='-' MK='*' KUD='Up/Dn' UP_ARR='^' DN_ARR='v' SEP='|' ELL='~'
fi

# ---------- state ----------
LVN=(ok INFO MED HIGH)
LVC=('90' '36' '33' '1;91')
P_PID=() P_PPID=() P_USR=() P_CPU=() P_ET=() P_EXE=() P_CWD=() P_CMD=()
P_UNIT=() P_PORTS=() P_LVL=() P_WHY=() P_KT=() P_PER=() P_ALW=()
K_TYPE=() K_WHO=() K_FILE=() K_LINE=() K_TXT=() K_LVL=() K_WHY=() K_ST=() K_BAK=() K_PID=()
declare -A PIDX=() PPIDOF=() PORTS=() EXPOSED=() OWNED=() ALLOW=() SELF=() MARK=()
LISTEN=() ORD=() KORD=() VIEW=()
A_TM=() A_ACT=() A_TGT=() A_USR=() A_EXE=() A_SHA=() A_RES=()
TAB=P FLT=1 AUTO=0 FILTER="" CUR=0 TOP=0 LH=10 REPN=0 LASTREF=0
NH=0 NM=0 NI=0 QH=0 QM=0
ST="" SC=32
KEY="" PVAL="" TG=() LT="" HS="" CH="" LASTERR="" REFUSE="" MKEY="" BK="" T=""
SAVED_STTY=""

SCRPAT='/dev/tcp/|(^|[ ;|&`(])(nc|ncat|netcat|socat) |bash -i|mkfifo|pty\.spawn|base64 +-d *\| *(ba)?sh|(curl|wget)[^|]*\| *(ba)?sh|eval *\( *base64_decode|system\(\$_(GET|POST|REQUEST)|socket.*(subprocess|pty|/bin/sh)|(subprocess|pty|/bin/sh).*socket'
SHPAT="$SCRPAT"'|curl |wget |/dev/tcp|nohup |/tmp/|/dev/shm/|/var/tmp/'
TMPRE='(/tmp/|/var/tmp/|/dev/shm/)'

log() { local m=${*//[[:cntrl:]]/?}; printf '%s %s\n' "$(date '+%F %T')" "$m" >>"$LOGFILE" 2>/dev/null; }

# ---------- terminal ----------
init_term() {
    SAVED_STTY=$(stty -g)
    stty -echo
    printf '\e[?1049h\e[?25l'
}
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
pager() { restore_term; less -R "$@"; init_term; }
say() { printf '\e[%d;1H\e[K\e[1;36m %s\e[0m' "$LINES" "$1" >&2; }

# readkey [timeout] -> KEY: a printable char, or UP DOWN LEFT RIGHT PGUP PGDN HOME END DEL ESC ENTER BS TAB NONE
readkey() {
    local k k2 k3 rest t=$1
    IFS= read -rsn1 ${t:+-t "$t"} k
    local rc=$?
    if ((rc > 128)); then KEY=NONE; return; fi
    case $k in
        '')       KEY=ENTER ;;
        $'\t')    KEY=TAB ;;
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

# ---------- helpers ----------
ltrunc() {  # ltrunc str width -> LT  (sanitised, keeps the tail)
    LT=${1//[[:cntrl:]]/?}
    ((${#LT} > $2)) && LT="$ELL${LT: -$(($2 - 1))}"
}
md() {  # md str -> MD  (safe inside a markdown table cell)
    local bt='`'
    MD=${1//|/\\|}; MD=${MD//"$bt"/\'}; MD=${MD//[[:cntrl:]]/?}
}
hms() {  # hms seconds -> HS
    local s=${1:-0}
    if ((s >= 86400)); then HS="$((s / 86400))d$((s % 86400 / 3600))h"
    elif ((s >= 3600)); then HS="$((s / 3600))h$((s % 3600 / 60))m"
    elif ((s >= 60)); then HS="$((s / 60))m$((s % 60))s"
    else HS="${s}s"; fi
}
active_line() {  # active_line "raw line" -> T=trimmed; true if non-blank, non-comment
    T=${1#"${1%%[![:space:]]*}"}
    [[ -n $T && $T != '#'* ]]
}
alt_path() {  # alt_path path -> ALT (usrmerge twin, or empty)
    ALT=""
    case $1 in
        /usr/bin/*)  ALT=/bin/${1#/usr/bin/} ;;
        /usr/sbin/*) ALT=/sbin/${1#/usr/sbin/} ;;
        /usr/lib/*)  ALT=/lib/${1#/usr/lib/} ;;
    esac
}
own_scan() {  # own_scan path... -> OWNED[path]=1 for dpkg-owned paths (one grep over all .list files)
    local pf p
    pf=$(mktemp) || return
    for p in "$@"; do
        [[ -z $p ]] && continue
        printf '%s\n' "$p" >>"$pf"
        alt_path "$p"; [[ -n $ALT ]] && printf '%s\n' "$ALT" >>"$pf"
    done
    while IFS= read -r p; do OWNED[$p]=1; done < <(grep -Fxh -f "$pf" /var/lib/dpkg/info/*.list 2>/dev/null)
    rm -f "$pf"
}
is_owned() {
    [[ -n ${OWNED[$1]} ]] && return 0
    alt_path "$1"
    [[ -n $ALT && -n ${OWNED[$ALT]} ]]
}
mk_of() { if [[ $TAB == P ]]; then MKEY=P${P_PID[$1]}; else MKEY=K$1; fi; }

load_allow() {
    ALLOW=(); local l
    [[ -f $ALLOWF ]] || return
    while IFS= read -r l; do [[ -n $l ]] && ALLOW[$l]=1; done <"$ALLOWF"
}
save_allow() {
    local k
    : >"$ALLOWF"; chmod 600 "$ALLOWF"
    for k in "${!ALLOW[@]}"; do printf '%s\n' "$k" >>"$ALLOWF"; done
}

# ---------- process scan ----------
flag() { ((LV < $1)) && LV=$1; WA+=("$2"); }

classify() {
    local i=$1 LV=0 WA=() e c ex b w s own=1 pid
    e=${P_EXE[i]} c=${P_CMD[i]} pid=${P_PID[i]}
    P_ALW[i]=""
    if ((P_KT[i])); then P_LVL[i]=0; P_WHY[i]="kernel thread"; return; fi
    if [[ -n ${SELF[$pid]} ]]; then P_LVL[i]=0; P_WHY[i]="this procwatch session"; return; fi
    ex=${e%' (deleted)'}; b=${ex##*/}; b=${b,,}

    [[ $e == *' (deleted)' ]] && { flag 3 "exe deleted from disk"; own=0; }
    [[ $ex =~ ^(/tmp|/var/tmp|/dev/shm|/home|/root)/ ]] && flag 3 "exe runs from ${ex%/*}"
    case $b in
        python*|perl*|ruby*|php*|node*|lua*|sh|bash|dash|zsh|ksh)
            [[ $c =~ (^|[[:space:]=])(/tmp/|/var/tmp/|/dev/shm/|/home/|/root/) ]] && flag 3 "interpreter runs a script from a temp/home path" ;;
    esac
    [[ $c =~ $SCRPAT ]] && flag 3 "reverse-shell / download-exec pattern"
    case $b in
        nc|ncat|netcat|nc.openbsd|nc.traditional|socat|nmap|john|hydra|hashcat|aircrack-ng|ettercap|medusa|ophcrack|xmrig|minerd|cpuminer|sqlmap|nikto|msfconsole|msfvenom|metasploit*)
            flag 3 "known hacking / miner tool" ;;
    esac
    [[ $c == '['* && ${P_PPID[i]} != 2 ]] && flag 3 "pretends to be a kernel thread"
    [[ $b == .* ]] && flag 2 "hidden file name"
    if ((own)); then
        case $ex in
            /snap/*|/usr/lib/snapd/*|/app/*|/newroot/*|/proc/*|'') ;;
            *) is_owned "$ex" || { own=0; flag 2 "exe not owned by any package"; } ;;
        esac
    fi
    [[ -n ${EXPOSED[$pid]} ]] && flag 2 "listens on high tcp port ${EXPOSED[$pid]% }"
    [[ ${P_CWD[i]} =~ ^(/tmp|/var/tmp|/dev/shm)(/|$) ]] && flag 2 "cwd in temp dir"
    [[ $c =~ (^|/)(python[0-9.]*|perl|ruby|php)[[:space:]]+-[a-zA-Z]*[ce][[:space:]] ]] && flag 2 "interpreter runs inline code"
    case $b in
        sshd|vsftpd|proftpd|pure-ftpd|apache2|httpd|nginx|mysqld|mariadbd|postgres|smbd|nmbd|telnetd|in.telnetd|xinetd|inetd|cupsd|postfix|master|dovecot|named|snmpd|rpcbind|vncserver|x11vnc|xvnc|tightvncserver|minidlna|in.tftpd|openvpn|avahi-daemon|bluetoothd|rsyncd|squid|dnsmasq)
            flag 1 "network service - check README" ;;
    esac
    if [[ -n ${ALLOW[$ex]} || ( -n ${P_UNIT[i]} && -n ${ALLOW[${P_UNIT[i]}]} ) ]]; then
        P_ALW[i]=1; LV=0; WA=("allowlisted")
    fi
    w=""; for s in "${WA[@]}"; do w+="${w:+; }$s"; done
    P_LVL[i]=$LV; P_WHY[i]=${w:-no flags}
}

collect_procs() {
    local -A exe=() cwd=()
    local d n l p pid ppid usr cpu et cmd i u c10 k
    while IFS=$'\t' read -r d n l; do
        p=${d##*/}; [[ $p == *[!0-9]* ]] && continue
        if [[ $n == exe ]]; then exe[$p]=$l; else cwd[$p]=$l; fi
    done < <(find /proc -mindepth 2 -maxdepth 2 \( -name exe -o -name cwd \) -printf '%h\t%f\t%l\n' 2>/dev/null)

    PORTS=() EXPOSED=() LISTEN=()
    local proto st rq sq loc peer users nm port addr re='"([^"]*)",pid=([0-9]+)(.*)'
    while read -r proto st rq sq loc peer users; do
        port=${loc##*:}; addr=${loc%:*}
        while [[ $users =~ $re ]]; do
            nm=${BASH_REMATCH[1]} pid=${BASH_REMATCH[2]} users=${BASH_REMATCH[3]}
            [[ ${PORTS[$pid]} == *"$proto:$port "* ]] || PORTS[$pid]+="$proto:$port "
            if [[ $proto == tcp && $port != *[!0-9]* && -n $port ]] && ((port > 1024)); then
                case $addr in 127.*|'[::1]') ;; *) EXPOSED[$pid]+="$port " ;; esac
            fi
            LISTEN+=("$proto"$'\t'"$addr"$'\t'"$port"$'\t'"$pid"$'\t'"$nm")
        done
    done < <(ss -tulpnH 2>/dev/null)

    local -a el=(); local -A seen=()
    for p in "${!exe[@]}"; do
        l=${exe[$p]%' (deleted)'}
        [[ -n $l && -z ${seen[$l]} ]] && { seen[$l]=1; el+=("$l"); }
    done
    own_scan "${el[@]}"

    P_PID=() P_PPID=() P_USR=() P_CPU=() P_ET=() P_EXE=() P_CWD=() P_CMD=()
    P_UNIT=() P_PORTS=() P_LVL=() P_WHY=() P_KT=() P_PER=() P_ALW=()
    PIDX=() PPIDOF=()
    i=0
    while read -r pid ppid usr cpu et cmd; do
        [[ -z $pid || $pid == *[!0-9]* ]] && continue
        PPIDOF[$pid]=$ppid; PIDX[$pid]=$i
        P_PID[i]=$pid P_PPID[i]=$ppid P_USR[i]=$usr P_CPU[i]=$cpu P_ET[i]=${et:-0} P_CMD[i]=$cmd
        P_EXE[i]=${exe[$pid]} P_CWD[i]=${cwd[$pid]} P_PORTS[i]=${PORTS[$pid]% } P_PER[i]="" P_UNIT[i]=""
        [[ -z ${exe[$pid]} ]] && P_KT[i]=1 || P_KT[i]=0
        if ((!P_KT[i])) && { read -r u <"/proc/$pid/cgroup"; } 2>/dev/null; then
            u=${u##*/}; [[ $u == *.service ]] && P_UNIT[i]=$u
        fi
        ((i++))
    done < <(ps -eo pid=,ppid=,user:20=,pcpu=,etimes=,args= 2>/dev/null)

    SELF=(); p=$$
    while [[ -n $p && $p -gt 1 ]]; do SELF[$p]=1; p=${PPIDOF[$p]}; done

    for i in "${!P_PID[@]}"; do classify "$i"; done
    crossref
    ORD=()
    while read -r l k; do ORD+=("$k"); done < <(
        for i in "${!P_PID[@]}"; do
            c10=${P_CPU[i]/./}; printf '%d %d %d\n' "${P_LVL[i]}" "$((10#${c10:-0}))" "$i"
        done | sort -k1,1nr -k2,2nr | while read -r a b c; do echo "$a $c"; done)
    recount
}

# ---------- persistence scan ----------
pk_add() {  # pk_add type who file line rawtext baselvl basewhy
    local JL=$6 JW=$7 j=${#K_TYPE[@]}
    if [[ $5 =~ $SCRPAT ]]; then JL=3 JW="reverse-shell / download-exec pattern"
    elif [[ $5 =~ $TMPRE ]]; then JL=3 JW="runs something from a temp dir"
    elif [[ $5 =~ (curl|wget)[[:space:]] ]]; then JL=3 JW="downloads from the network"
    fi
    K_TYPE[j]=$1 K_WHO[j]=$2 K_FILE[j]=$3 K_LINE[j]=$4 K_TXT[j]=$5 K_LVL[j]=$JL K_WHY[j]=$JW K_ST[j]="" K_BAK[j]="" K_PID[j]=""
}

kdisp() {  # kdisp j -> LT (short, sanitised text for the row)
    local j=$1 t=${K_TXT[$1]} a
    t=${t//[[:cntrl:]]/ }; t=${t#"${t%%[![:space:]]*}"}
    if [[ ${K_TYPE[j]} == SSH && $t =~ ^(ssh-|ecdsa-|sk-) ]]; then
        a=${t%% *}; t="$a key ...${t##* }"
    fi
    LT=$t
}

scan_persist() {
    K_TYPE=() K_WHO=() K_FILE=() K_LINE=() K_TXT=() K_LVL=() K_WHY=() K_ST=() K_BAK=() K_PID=()
    local u uid home f n l t h b j
    local -a users=() homes=() cand=() rcf=()
    say "Scanning persistence (cron, units, autostart, rc, ssh keys, shell files)..."
    while IFS=: read -r u _ uid _ _ home _; do
        if [[ $uid != *[!0-9]* && -n $uid ]] && { ((uid == 0 || uid >= 1000)) && ((uid != 65534)); } && [[ -d $home ]]; then
            users+=("$u"); homes+=("$home")
        fi
    done < <(getent passwd)

    for f in /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* \
             /etc/init.d/* /etc/profile.d/* /etc/xdg/autostart/*.desktop \
             /etc/systemd/system/*.service /etc/systemd/system/*.timer \
             /usr/local/lib/systemd/system/*.service /usr/local/lib/systemd/system/*.timer \
             /etc/systemd/user/*.service /etc/rc.local; do
        [[ -f $f && ! -L $f ]] && cand+=("$f")
    done
    own_scan "${cand[@]}"

    # --- cron: user crontabs
    for u in "${users[@]}"; do
        n=0
        while IFS= read -r l; do
            ((n++))
            active_line "$l" || continue
            [[ $T =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] && continue
            pk_add CRON "$u" "crontab:$u" "$n" "$l" 2 "user crontab entry"
        done < <(crontab -l -u "$u" 2>/dev/null)
    done
    # --- cron: system files
    for f in /etc/crontab /etc/cron.d/*; do
        [[ -f $f ]] || continue
        [[ $f == /etc/cron.d/* ]] && is_owned "$f" && continue
        n=0
        while IFS= read -r l || [[ -n $l ]]; do
            ((n++))
            active_line "$l" || continue
            [[ $T =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] && continue
            if [[ $f == /etc/crontab && $T == *run-parts* ]]; then pk_add CRON root "$f" "$n" "$l" 0 "stock run-parts line"
            else pk_add CRON root "$f" "$n" "$l" 2 "cron line in ${f##*/}"; fi
        done <"$f"
    done
    for f in /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*; do
        [[ -f $f && ! -L $f ]] && ! is_owned "$f" && pk_add CRON root "$f" 0 "script in ${f%/*}" 2 "unpackaged cron script"
    done
    # --- systemd units, autostart, init.d, rc.local (system)
    for f in /etc/systemd/system/*.service /etc/systemd/system/*.timer /usr/local/lib/systemd/system/*.service \
             /usr/local/lib/systemd/system/*.timer /etc/systemd/user/*.service; do
        [[ -f $f && ! -L $f ]] || continue
        is_owned "$f" && continue
        t=$(grep -m3 -E '^Exec' "$f" 2>/dev/null | tr '\n' ' ')
        pk_add UNIT root "$f" 0 "${t:-$f}" 2 "unpackaged unit file"
    done
    for f in /etc/xdg/autostart/*.desktop; do
        [[ -f $f ]] && ! is_owned "$f" || continue
        t=$(grep -m1 '^Exec=' "$f" 2>/dev/null)
        pk_add AUTO root "$f" 0 "${t:-$f}" 2 "unpackaged autostart entry"
    done
    for f in /etc/init.d/*; do
        [[ -f $f && ! -L $f ]] && ! is_owned "$f" && pk_add INITD root "$f" 0 "init script $f" 2 "unpackaged init.d script"
    done
    if [[ -f /etc/rc.local ]]; then
        n=0
        while IFS= read -r l || [[ -n $l ]]; do
            ((n++))
            active_line "$l" || continue
            [[ $T == 'exit 0' ]] && continue
            pk_add RC root /etc/rc.local "$n" "$l" 2 "rc.local command"
        done </etc/rc.local
    fi
    for f in /etc/profile.d/*; do
        [[ -f $f && ! -L $f ]] && ! is_owned "$f" && pk_add SHELL root "$f" 0 "profile.d script $f" 2 "unpackaged profile.d script"
    done
    # --- per-user: autostart, user units, ssh keys, shell files
    for h in "${homes[@]}"; do
        u=$(stat -c %U "$h" 2>/dev/null)
        for f in "$h"/.config/autostart/*.desktop; do
            [[ -f $f ]] || continue
            grep -qE '^(Hidden=true|X-GNOME-Autostart-enabled=false)' "$f" 2>/dev/null && continue
            t=$(grep -m1 '^Exec=' "$f" 2>/dev/null)
            pk_add AUTO "$u" "$f" 0 "${t:-$f}" 2 "user autostart entry"
        done
        for f in "$h"/.config/systemd/user/*.service "$h"/.config/systemd/user/*.timer; do
            [[ -f $f && ! -L $f ]] || continue
            t=$(grep -m3 -E '^Exec' "$f" 2>/dev/null | tr '\n' ' ')
            pk_add UNIT "$u" "$f" 0 "${t:-$f}" 2 "user systemd unit"
        done
        for f in "$h"/.ssh/authorized_keys*; do
            [[ -f $f ]] || continue
            n=0
            while IFS= read -r l || [[ -n $l ]]; do
                ((n++))
                active_line "$l" || continue
                pk_add SSH "$u" "$f" "$n" "$l" 2 "authorized ssh key"
            done <"$f"
        done
        for b in .bashrc .profile .bash_profile .bash_login .bash_logout .zshrc .zprofile .xprofile .xsessionrc; do
            [[ -f $h/$b ]] && rcf+=("$h/$b")
        done
    done
    rcf+=(/etc/profile /etc/bash.bashrc)
    while IFS= read -r l; do
        f=${l%%:*}; l=${l#*:}; n=${l%%:*}; t=${l#*:}
        active_line "$t" || continue
        pk_add SHELL "$(stat -c %U "$f" 2>/dev/null)" "$f" "$n" "$t" 2 "suspicious line in shell startup file"
    done < <(grep -nHE -e "$SHPAT" "${rcf[@]}" 2>/dev/null)

    crossref
    KORD=()
    while read -r l t; do KORD+=("$t"); done < <(
        for j in "${!K_TYPE[@]}"; do printf '%d %d\n' "${K_LVL[j]}" "$j"; done | sort -k1,1nr -k2,2n)
    recount
}

crossref() {  # link persistence rows to running unpackaged / suspicious processes
    local i j e
    for i in "${!P_PID[@]}"; do P_PER[i]=""; done
    ((${#K_TYPE[@]})) || return
    for j in "${!K_TYPE[@]}"; do K_PID[j]=""; done
    for i in "${!P_PID[@]}"; do
        ((P_KT[i] || P_LVL[i] < 2)) && continue
        e=${P_EXE[i]%' (deleted)'}
        [[ -z $e ]] && continue
        for j in "${!K_TYPE[@]}"; do
            if [[ ${K_TXT[j]} == *"$e"* ]]; then
                K_PID[j]+="${P_PID[i]} "; P_PER[i]=1
                ((K_LVL[j] < 3)) && K_LVL[j]=3
                [[ ${K_WHY[j]} == *"launches running"* ]] || K_WHY[j]+="; launches running process"
            fi
        done
        [[ -n ${P_PER[i]} && ${P_WHY[i]} != *"persistence"* ]] && P_WHY[i]+="; started by a persistence entry"
    done
}

recount() {
    NH=0 NM=0 NI=0 QH=0 QM=0
    local i j
    for i in "${!P_PID[@]}"; do
        ((P_KT[i])) && continue
        case ${P_LVL[i]} in 3) ((NH++)) ;; 2) ((NM++)) ;; 1) ((NI++)) ;; esac
    done
    for j in "${!K_TYPE[@]}"; do
        [[ -n ${K_ST[j]} ]] && continue
        case ${K_LVL[j]} in 3) ((QH++)) ;; 2) ((QM++)) ;; esac
    done
}

# ---------- view ----------
clamp() {
    local n=${#VIEW[@]}
    ((CUR >= n)) && CUR=$((n - 1))
    ((CUR < 0)) && CUR=0
    ((CUR < TOP)) && TOP=$CUR
    ((CUR >= TOP + LH)) && TOP=$((CUR - LH + 1))
    ((TOP < 0)) && TOP=0
}

build_view() {  # build_view [keep-key]  (pid on Processes tab, row index on Persistence)
    local key=$1 i j f=${FILTER,,} txt thr
    if [[ -z $key ]] && ((${#VIEW[@]})); then
        if [[ $TAB == P ]]; then key=${P_PID[${VIEW[CUR]}]}; else key=${VIEW[CUR]}; fi
    fi
    VIEW=()
    if [[ $TAB == P ]]; then
        for i in "${ORD[@]}"; do
            ((P_KT[i] && FLT != 4)) && continue
            case $FLT in
                1) ((P_LVL[i] >= 2)) || continue ;;
                2) ((P_LVL[i] >= 1)) || continue ;;
                3) [[ -n ${P_PORTS[i]} ]] || continue ;;
            esac
            if [[ -n $f ]]; then
                txt="${P_USR[i]} ${P_UNIT[i]} ${P_CMD[i]}"
                [[ ${txt,,} == *"$f"* ]] || continue
            fi
            VIEW+=("$i")
        done
    else
        case $FLT in 1) thr=2 ;; 4) thr=0 ;; *) thr=1 ;; esac
        for j in "${KORD[@]}"; do
            ((K_LVL[j] >= thr)) || [[ -n ${K_ST[j]} ]] || continue
            if [[ -n $f ]]; then
                txt="${K_TYPE[j]} ${K_WHO[j]} ${K_FILE[j]} ${K_TXT[j]}"
                [[ ${txt,,} == *"$f"* ]] || continue
            fi
            VIEW+=("$j")
        done
    fi
    CUR=0
    if [[ -n $key ]]; then
        for j in "${!VIEW[@]}"; do
            if [[ $TAB == P ]]; then [[ ${P_PID[${VIEW[j]}]} == "$key" ]] && { CUR=$j; break; }
            else [[ ${VIEW[j]} == "$key" ]] && { CUR=$j; break; }; fi
        done
    fi
    clamp
}

refresh_procs() {
    local key=""
    if [[ $TAB == P ]] && ((${#VIEW[@]})); then key=${P_PID[${VIEW[CUR]}]}; fi
    collect_procs
    LASTREF=$SECONDS
    if [[ $TAB == P ]]; then build_view "${key:-0}"; fi
}

rescan_persist() {
    local key=""
    if [[ $TAB == K ]] && ((${#VIEW[@]})); then key=${VIEW[CUR]}; fi
    scan_persist
    MARK=()
    build_view
}

# ---------- drawing ----------
draw() {
    local W=$COLUMNS i j row idx buf nu=${#VIEW[@]} left right sp hdr cmdw nm=${#MARK[@]}
    LH=$((LINES - 5)); ((LH < 1)) && LH=1
    clamp

    if [[ $TAB == P ]]; then left=" Process Watch  [Processes] Persistence"; else left=" Process Watch  Processes [Persistence]"; fi
    right="proc H:$NH M:$NM I:$NI $SEP pers H:$QH M:$QM $SEP $nm marked "
    ((AUTO)) && right="auto $right"
    [[ -n $FILTER ]] && right="[/$FILTER] $right"
    printf -v sp '%*s' $((W - ${#left} - ${#right} > 0 ? W - ${#left} - ${#right} : 1)) ''
    buf=$'\e[H\e[1;97;44m'"${left}${sp}${right}"$'\e[0m\e[K\n'

    if [[ $TAB == P ]]; then
        printf -v hdr ' %s %-4s %7s %-9s %5s %-12s %-14s %s' ' ' LVL PID USER CPU PORTS UNIT COMMAND
    else
        printf -v hdr ' %s %-4s %-5s %-9s %-8s %-14s %s' ' ' LVL TYPE WHO STATE FILE:LINE TEXT
    fi
    buf+=$'\e[1;36m'"${hdr:0:W}"$'\e[0m\e[K\n'

    cmdw=$((W - 60)); ((cmdw < 10)) && cmdw=10
    for ((row = 0; row < LH; row++)); do
        idx=$((TOP + row))
        if ((idx >= nu)); then
            if ((nu == 0 && row == 0)); then buf+=$'\e[2m  (nothing matches this filter - 4 shows everything)\e[0m\e[K\n'; else buf+=$'\e[K\n'; fi
            continue
        fi
        i=${VIEW[idx]}
        local base=$'\e[39m' pre="" part line lv lbl lc mk=" "
        ((idx == CUR)) && { pre=$'\e[48;5;24m'; base=$'\e[97m'; }
        mk_of "$i"; [[ -n ${MARK[$MKEY]} ]] && mk="$MK"
        if [[ $TAB == P ]]; then
            lv=${P_LVL[i]}; lbl=${LVN[lv]}; lc=${LVC[lv]}
            ((P_KT[i])) && { lbl="kern"; lc=90; }
            [[ -n ${P_ALW[i]} ]] && { lbl="ALW"; lc=90; }
            line="$pre$base "$'\e[92m'"$mk$base "
            printf -v part '%-4s' "$lbl"; line+=$'\e['"$lc"'m'"$part$base "
            printf -v part '%7s %-9.9s %5s %-12.12s ' "${P_PID[i]}" "${P_USR[i]}" "${P_CPU[i]}" "${P_PORTS[i]}"; line+="$part"
            local un=${P_UNIT[i]%.service}; [[ -n ${P_PER[i]} ]] && un="PERSIST${un:+ $un}"
            printf -v part '%-14.14s ' "$un"; line+=$'\e[33m'"$part$base"
            local c=${P_CMD[i]//[[:cntrl:]]/?}; line+="${c:0:cmdw}"
        else
            lv=${K_LVL[i]}; lbl=${LVN[lv]}; lc=${LVC[lv]}
            local st=${K_ST[i]:-${K_PID[i]:+RUNS}}
            [[ -n ${K_ST[i]} ]] && { base=$'\e[90m'; ((idx == CUR)) && base=$'\e[37m'; lc=90; }
            line="$pre$base "$'\e[92m'"$mk$base "
            printf -v part '%-4s' "$lbl"; line+=$'\e['"$lc"'m'"$part$base "
            printf -v part '%-5.5s %-9.9s ' "${K_TYPE[i]}" "${K_WHO[i]}"; line+="$part"
            printf -v part '%-8.8s ' "$st"; line+=$'\e[33m'"$part$base"
            local fl=${K_FILE[i]}; ((K_LINE[i] > 0)) && fl+=":${K_LINE[i]}"
            ltrunc "$fl" 14; printf -v part '%-14s ' "$LT"; line+="$part"
            kdisp "$i"; line+="${LT:0:cmdw}"
        fi
        buf+="$line"$'\e[0m\e[K\n'
    done

    local info=""
    ((TOP > 0)) && info+=" $UP_ARR more "
    ((TOP + LH < nu)) && info+=" $DN_ARR more "
    local rule; printf -v rule '%*s' $((W - ${#info})) ''
    buf+=$'\e[2m'"${rule// /$HR}${info}"$'\e[0m\e[K\n'

    local stt=$ST sc=$SC
    if [[ -z $stt && $nu -gt 0 ]]; then
        i=${VIEW[CUR]}; sc=36
        if [[ $TAB == P ]]; then stt="${P_WHY[i]}  |  ${P_EXE[i]}"; ((P_LVL[i] >= 3)) && sc=91; ((P_LVL[i] == 2)) && sc=33
        else stt="${K_WHY[i]}${K_PID[i]:+ (PID ${K_PID[i]% })}  |  ${K_FILE[i]}"; ((K_LVL[i] >= 3)) && sc=91; ((K_LVL[i] == 2)) && sc=33; fi
    fi
    stt=${stt//[[:cntrl:]]/?}
    buf+=$'\e['"$sc"'m '"${stt:0:W-2}"$'\e[0m\e[K\n'

    local -a hints
    if [[ $TAB == P ]]; then
        hints=("$KUD:move" "Space:mark" "x:kill" "X:kill -9" "S:stop unit" "Enter:inspect" "Tab:persist" "1-4:filter" "w:allow" "t:auto" "R:report" "?:help" "q:quit")
    else
        hints=("$KUD:move" "Space:mark" "d:disable" "u:undo" "Enter:inspect" "Tab:procs" "1-4:filter" "s:rescan" "R:report" "?:help" "q:quit")
    fi
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
    local lines=(
        "KEYBINDS"
        ""
        "  Up/Down  j/k       move                PgUp/PgDn  Home/End  g/G   jump"
        "  Tab                switch Processes / Persistence"
        "  Space              mark / unmark       a  mark all visible   A  clear marks"
        "  Enter  v           inspect in a pager (exe, sha256, package owner, fds, parents, ...)"
        "  x                  kill (SIGTERM) marked or highlighted processes"
        "  X                  kill -9 (SIGKILL)"
        "  S                  stop the highlighted process's systemd unit (then asks: disable? mask?)"
        "  d                  Persistence: disable marked/highlighted items (original is backed up first)"
        "  u                  Persistence: undo a disable"
        "  1-4                Processes: 1 suspicious  2 +services  3 listening  4 all incl. kernel threads"
        "                     Persistence: 1 suspicious  2/3 non-stock  4 everything"
        "  /                  text filter         Esc clears it"
        "  r                  refresh (Processes) / rescan (Persistence)    s  rescan persistence"
        "  t                  toggle 5s auto-refresh of the process list"
        "  w                  allowlist the highlighted process's unit/exe (README-required stuff)"
        "  L                  view session log    R  write Markdown report    q  quit"
        ""
        "LVL: HIGH deleted exe / temp or home path / reverse-shell pattern / hacking tool"
        "     MED  unpackaged exe / high tcp port / hidden name / inline interpreter / cwd in /tmp"
        "     INFO network service - check the README    RUNS = persistence row launches a live process"
        ""
        "Nothing is touched without a yes. PID 1, kernel threads, this tool's own shell/terminal and"
        "/opt/CyberPatriot are refused. Remove persistence first (d), then kill, or it restarts."
        "Log: $LOGFILE   Backups: $BAKROOT   Allowlist: $ALLOWF"
        ""
        "  press any key"
    )
    local buf=$'\e[H\e[J\e[1;97;44m' sp l
    printf -v sp '%*s' "$COLUMNS" ''
    buf+=" Help${sp:5}"$'\e[0m\n\n'
    for l in "${lines[@]}"; do buf+="$l"$'\n'; done
    printf '%s' "$buf"
    readkey
}

# ---------- prompts ----------
prompt() {   # prompt "label" [secret] [default] -> PVAL ; returns 1 on Esc
    local label=${1//[[:cntrl:]]/?} s=${3:-}
    printf '\e[?25h'
    while :; do
        local room=$((COLUMNS - ${#label} - 4)) disp=$s
        ((${#disp} > room)) && disp="$ELL${disp: -$((room - 1))}"
        printf '\e[%d;1H\e[K\e[1;36m %s\e[0m %s' "$LINES" "$label" "$disp"
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
    local def=${2:-n} hint='[y/N]' q=${1//[[:cntrl:]]/?}
    [[ $def == y ]] && hint='[Y/n]'
    printf '\e[%d;1H\e[K\e[1;33m %s %s\e[0m' "$LINES" "${q:0:COLUMNS-12}" "$hint"
    while :; do
        readkey
        case $KEY in
            y|Y) return 0 ;;
            n|N|ESC) return 1 ;;
            ENTER) [[ $def == y ]]; return ;;
        esac
    done
}

ynq() {  # ynq "text" -> 0 yes, 1 no, 2 quit
    local q=${1//[[:cntrl:]]/?}
    printf '\e[%d;1H\e[K\e[1;33m %s \e[0m[y/n/q]' "$LINES" "${q:0:COLUMNS-12}"
    while :; do
        readkey
        case $KEY in y|Y) return 0 ;; n|N) return 1 ;; q|Q|ESC) return 2 ;; esac
    done
}

choose() {  # choose "text" -> CH = a|o|n
    local q=${1//[[:cntrl:]]/?}
    printf '\e[%d;1H\e[K\e[1;33m %s\e[0m' "$LINES" "${q:0:COLUMNS-2}"
    while :; do
        readkey
        case $KEY in
            a|A) CH=a; return 0 ;;
            o|O) CH=o; return 0 ;;
            n|N|ESC|q) CH=n; return 1 ;;
        esac
    done
}

# ---------- actions ----------
summary() {  # summary "verb" ok fail
    if (($3 == 0)); then ST="$1: $2 item(s)"; SC=32
    else ST="$1: $2 ok, $3 failed - $LASTERR"; SC=31; fi
}

targets() {  # targets [state]  -> TG: marked visible items, else the cursor item (Persistence: filtered by state)
    TG=(); local i want=$1
    for i in "${VIEW[@]}"; do
        mk_of "$i"; [[ -n ${MARK[$MKEY]} ]] || continue
        [[ $TAB == K && ${K_ST[i]} != "$want" ]] && continue
        TG+=("$i")
    done
    if ((${#TG[@]} == 0 && ${#VIEW[@]} > 0)); then
        i=${VIEW[CUR]}
        if [[ $TAB == P || ${K_ST[i]} == "$want" ]]; then TG=("$i"); fi
    fi
}

record() {  # record action target user exe sha result
    A_TM+=("$(date +%T)") A_ACT+=("$1") A_TGT+=("$2") A_USR+=("$3") A_EXE+=("$4") A_SHA+=("$5") A_RES+=("$6")
    log "$6 $1 target=[$2] user=$3 exe=$4 sha256=$5"
}

alive() { [[ -d /proc/$1 ]] && ! grep -q '^State:[[:space:]]*Z' "/proc/$1/status" 2>/dev/null; }
wait_gone() { local n; for n in 1 2 3 4 5 6 7 8 9 10; do alive "$1" || return 0; sleep 0.2; done; ! alive "$1"; }

refuse_reason() {  # refuse_reason idx -> REFUSE (empty when allowed)
    local i=$1 pid=${P_PID[$1]}
    REFUSE=""
    if ((pid == 1)); then REFUSE="PID 1"
    elif ((P_KT[i])); then REFUSE="kernel thread"
    elif [[ -n ${SELF[$pid]} ]]; then REFUSE="part of this tool's own shell/terminal session"
    elif [[ ${P_CMD[i]} == *CyberPatriot* || ${P_EXE[i]} == /opt/CyberPatriot* ]]; then REFUSE="CyberPatriot scoring client"
    fi
}

needs_typed() {  # critical system service owned by root -> true
    local b=${P_EXE[$1]%' (deleted)'}; b=${b##*/}
    [[ ${P_USR[$1]} == root ]] || return 1
    case $b in
        systemd*|dbus*|Xorg|Xwayland|lightdm*|gdm*|cinnamon*|NetworkManager|sshd|cron|rsyslogd|polkitd|agetty|login|udisksd|accounts-daemon) return 0 ;;
    esac
    return 1
}

act_kill() {  # act_kill 15|9
    local sig=$1 sn=TERM i ok=0 fail=0 rc pid cur sha b
    local -a go=()
    [[ $sig == 9 ]] && sn=KILL
    [[ $TAB == P ]] || { ST="Switch to the Processes tab (Tab)"; SC=33; return; }
    targets ""
    ((${#TG[@]})) || { ST="Nothing selected"; SC=33; return; }
    for i in "${TG[@]}"; do
        refuse_reason "$i"
        if [[ -n $REFUSE ]]; then log "REFUSED kill pid=${P_PID[i]} $REFUSE"; LASTERR="refused PID ${P_PID[i]}: $REFUSE"; ((fail++)); continue; fi
        go+=("$i")
    done
    if ((${#go[@]} == 0)); then ST="$LASTERR"; SC=31; return; fi
    choose "SIG$sn ${#go[@]} process(es)  -  [a]ll / [o]ne-by-one / [n]o" || { ST="Cancelled"; SC=33; return; }
    for i in "${go[@]}"; do
        pid=${P_PID[i]}
        if [[ $CH == o ]]; then
            ltrunc "[${LVN[P_LVL[i]]}] $pid ${P_USR[i]} ${P_CMD[i]}" $((COLUMNS - 20))
            ynq "$LT"; rc=$?
            ((rc == 2)) && break
            ((rc == 1)) && continue
        fi
        cur=$(readlink "/proc/$pid/exe" 2>/dev/null)
        if [[ $cur != "${P_EXE[i]}" ]]; then LASTERR="PID $pid changed or exited - refresh (r)"; ((fail++)); continue; fi
        b=${P_EXE[i]%' (deleted)'}; b=${b##*/}
        if needs_typed "$i"; then
            prompt "Critical service. Type KILL to stop $b ($pid):" 0 || continue
            [[ $PVAL == KILL ]] || continue
        fi
        if [[ -n ${P_UNIT[i]} || -n ${P_PER[i]} ]]; then
            confirm "PID $pid will likely restart (${P_UNIT[i]:-persistence entry}). Kill anyway?" n || continue
        fi
        sha=$(sha256sum "/proc/$pid/exe" 2>/dev/null | cut -c1-64)
        kill -"$sig" "$pid" 2>/dev/null
        wait_gone "$pid"
        if alive "$pid" && [[ $sig == 15 ]]; then
            if confirm "PID $pid still running after SIGTERM. Send SIGKILL?" n; then
                kill -9 "$pid" 2>/dev/null; sn=KILL; wait_gone "$pid"
            fi
        fi
        if alive "$pid"; then
            LASTERR="PID $pid still running"; ((fail++)); record "kill" "pid $pid ${P_CMD[i]:0:80}" "${P_USR[i]}" "${P_EXE[i]}" "${sha:--}" FAIL
        else
            ((ok++)); unset "MARK[P$pid]"
            record "kill SIG$sn" "pid $pid ${P_CMD[i]:0:80}" "${P_USR[i]}" "${P_EXE[i]}" "${sha:--}" OK
        fi
        sn=TERM; [[ $sig == 9 ]] && sn=KILL
    done
    refresh_procs
    summary "Killed" "$ok" "$fail"
}

act_stop() {
    [[ $TAB == P ]] || { ST="Switch to the Processes tab (Tab)"; SC=33; return; }
    ((${#VIEW[@]})) || return
    local i=${VIEW[CUR]} unit=${P_UNIT[${VIEW[CUR]}]} sha
    [[ -n $unit ]] || { ST="This process has no systemd service unit"; SC=33; return; }
    refuse_reason "$i"
    [[ -n $REFUSE ]] && { ST="Refused: $REFUSE"; SC=31; return; }
    if needs_typed "$i"; then
        prompt "Critical service. Type STOP to stop $unit:" 0 || { ST="Cancelled"; SC=33; return; }
        [[ $PVAL == STOP ]] || { ST="Cancelled"; SC=33; return; }
    fi
    confirm "systemctl stop $unit ?" n || { ST="Cancelled"; SC=33; return; }
    sha=$(sha256sum "/proc/${P_PID[i]}/exe" 2>/dev/null | cut -c1-64)
    if systemctl stop "$unit" 2>/dev/null; then record "systemctl stop" "$unit" "${P_USR[i]}" "${P_EXE[i]}" "${sha:--}" OK; ST="Stopped $unit"; SC=32
    else record "systemctl stop" "$unit" "${P_USR[i]}" "${P_EXE[i]}" "${sha:--}" FAIL; ST="Could not stop $unit"; SC=31; return; fi
    if confirm "Also DISABLE $unit (do not start at boot)?" n; then
        systemctl disable "$unit" >/dev/null 2>&1 && { record "systemctl disable" "$unit" "${P_USR[i]}" "${P_EXE[i]}" - OK; ST+=" + disabled"; }
    fi
    if confirm "Also MASK $unit (cannot be started at all)?" n; then
        systemctl mask "$unit" >/dev/null 2>&1 && { record "systemctl mask" "$unit" "${P_USR[i]}" "${P_EXE[i]}" - OK; ST+=" + masked"; }
    fi
    refresh_procs
}

act_allow() {
    [[ $TAB == P ]] || return
    ((${#VIEW[@]})) || return
    local i=${VIEW[CUR]} k
    k=${P_UNIT[i]:-${P_EXE[i]%' (deleted)'}}
    [[ -n $k ]] || return
    if [[ -n ${ALLOW[$k]} ]]; then
        confirm "Remove $k from the allowlist?" n || { ST="Cancelled"; SC=33; return; }
        unset "ALLOW[$k]"; ST="Un-allowlisted $k"
    else
        confirm "Allowlist $k (mark as README-approved, level cleared)?" n || { ST="Cancelled"; SC=33; return; }
        ALLOW[$k]=1; ST="Allowlisted $k"
    fi
    SC=36; save_allow; log "allowlist $k now: ${ALLOW[$k]:+yes}"
    refresh_procs
}

# --- persistence edits (always back up first)
bak_copy() {  # bak_copy file -> BK
    local dst=$BAKDIR/${1//\//_}
    mkdir -p "$BAKDIR" && chmod 700 "$BAKROOT" "$BAKDIR" 2>/dev/null
    [[ -e $dst ]] || cp -p -- "$1" "$dst" 2>/dev/null
    BK=$dst
}
edit_line() {  # edit_line file n rawtext disable|enable
    local f=$1 n=$2 t=$3 mode=$4 cur
    cur=$(sed -n "${n}p" "$f" 2>/dev/null)
    if [[ $mode == disable ]]; then
        [[ $cur == "$t" ]] || { LASTERR="line changed since scan - rescan (s)"; return 1; }
        sed -i "${n}s/^/# procwatch-disabled: /" "$f"
    else
        [[ $cur == "# procwatch-disabled: $t" ]] || { LASTERR="line is not in disabled state"; return 1; }
        sed -i "${n}s/^# procwatch-disabled: //" "$f"
    fi
}
edit_cron() {  # edit_cron user n rawtext disable|enable
    local u=$1 tmp rc
    tmp=$(mktemp) || return 1
    crontab -l -u "$u" >"$tmp" 2>/dev/null
    edit_line "$tmp" "$2" "$3" "$4" && crontab -u "$u" "$tmp" 2>/dev/null
    rc=$?
    rm -f "$tmp"
    ((rc)) && [[ -z $LASTERR ]] && LASTERR="crontab update failed"
    return $rc
}

do_disable() {  # do_disable j -> 0 ok ; sets LASTERR
    local j=$1 f=${K_FILE[$1]} n=${K_LINE[$1]} u dst sha="-" loc=""
    ((n > 0)) && loc=":$n"
    LASTERR=""
    [[ -f $f ]] && sha=$(sha256sum "$f" 2>/dev/null | cut -c1-64)
    if [[ $f == crontab:* ]]; then
        u=${f#crontab:}
        mkdir -p "$BAKDIR" && chmod 700 "$BAKROOT" "$BAKDIR" 2>/dev/null
        [[ -e $BAKDIR/crontab-$u ]] || crontab -l -u "$u" >"$BAKDIR/crontab-$u" 2>/dev/null
        K_BAK[j]=$BAKDIR/crontab-$u
        edit_cron "$u" "$n" "${K_TXT[j]}" disable || return 1
    elif [[ ${K_TYPE[j]} == UNIT ]]; then
        bak_copy "$f"; K_BAK[j]=$BK
        systemctl disable --now "${f##*/}" >/dev/null 2>&1 || { LASTERR="systemctl disable failed"; return 1; }
    elif ((n > 0)); then
        bak_copy "$f"; K_BAK[j]=$BK
        edit_line "$f" "$n" "${K_TXT[j]}" disable || return 1
    else
        mkdir -p "$BAKDIR/moved" && chmod 700 "$BAKROOT" "$BAKDIR" 2>/dev/null
        dst=$BAKDIR/moved/${f//\//_}
        mv -- "$f" "$dst" 2>/dev/null || { LASTERR="mv failed"; return 1; }
        K_BAK[j]=$dst
    fi
    K_ST[j]=DISABLED
    record "disable ${K_TYPE[j]}" "$f$loc  ${K_TXT[j]:0:60}" "${K_WHO[j]}" "-" "${sha:--}" OK
}

do_undo() {  # do_undo j
    local j=$1 f=${K_FILE[$1]} n=${K_LINE[$1]} u loc=""
    ((n > 0)) && loc=":$n"
    LASTERR=""
    if [[ $f == crontab:* ]]; then
        u=${f#crontab:}; edit_cron "$u" "$n" "${K_TXT[j]}" enable || return 1
    elif [[ ${K_TYPE[j]} == UNIT ]]; then
        [[ -f $f ]] || { LASTERR="unit file gone"; return 1; }
        systemctl enable "${f##*/}" >/dev/null 2>&1 || { LASTERR="systemctl enable failed"; return 1; }
    elif ((n > 0)); then
        edit_line "$f" "$n" "${K_TXT[j]}" enable || return 1
    else
        [[ -e $f ]] && { LASTERR="original path exists"; return 1; }
        mv -- "${K_BAK[j]}" "$f" 2>/dev/null || { LASTERR="mv failed"; return 1; }
    fi
    K_ST[j]=""
    record "restore ${K_TYPE[j]}" "$f$loc" "${K_WHO[j]}" "-" "-" OK
}

act_disable() {
    [[ $TAB == K ]] || { ST="Switch to the Persistence tab (Tab)"; SC=33; return; }
    targets ""
    ((${#TG[@]})) || { ST="Nothing to disable here (already disabled?)"; SC=33; return; }
    local j ok=0 fail=0 rc
    choose "DISABLE ${#TG[@]} persistence item(s), originals backed up  -  [a]ll / [o]ne-by-one / [n]o" || { ST="Cancelled"; SC=33; return; }
    for j in "${TG[@]}"; do
        if [[ $CH == o ]]; then
            kdisp "$j"; ltrunc "[${K_TYPE[j]}] ${K_WHO[j]} ${K_FILE[j]} $LT" $((COLUMNS - 20))
            ynq "$LT"; rc=$?
            ((rc == 2)) && break
            ((rc == 1)) && continue
        fi
        if do_disable "$j"; then ((ok++)); unset "MARK[K$j]"; else ((fail++)); log "FAIL disable ${K_FILE[j]}: $LASTERR"; fi
    done
    recount; build_view
    summary "Disabled" "$ok" "$fail"
    ((ok)) && ST+=" (u undoes, backups: $BAKDIR). Now kill the process."
}

act_undo() {
    [[ $TAB == K ]] || return
    targets DISABLED
    ((${#TG[@]})) || { ST="Nothing disabled is selected"; SC=33; return; }
    confirm "Restore ${#TG[@]} item(s) to their original state?" n || { ST="Cancelled"; SC=33; return; }
    local j ok=0 fail=0
    for j in "${TG[@]}"; do
        if do_undo "$j"; then ((ok++)); unset "MARK[K$j]"; else ((fail++)); log "FAIL restore ${K_FILE[j]}: $LASTERR"; fi
    done
    recount; build_view
    summary "Restored" "$ok" "$fail"
}

# ---------- inspect ----------
inspect_proc() {
    local i=$1 pid=${P_PID[$1]} ex p d j
    ex=${P_EXE[i]%' (deleted)'}
    hms "${P_ET[i]}"
    printf 'PID    : %s   PPID: %s   User: %s   CPU: %s%%   Running: %s\n' "$pid" "${P_PPID[i]}" "${P_USR[i]}" "${P_CPU[i]}" "$HS"
    printf 'Level  : %s - %s\n' "${LVN[P_LVL[i]]}" "${P_WHY[i]}"
    printf 'Cmdline: %s\n' "$(tr -c '[:print:]' ' ' <"/proc/$pid/cmdline" 2>/dev/null)"
    printf 'Exe    : %s\n' "${P_EXE[i]}"
    printf 'Cwd    : %s\n' "${P_CWD[i]}"
    printf 'Unit   : %s\n' "${P_UNIT[i]:--}"
    printf 'Ports  : %s\n' "${P_PORTS[i]:--}"
    printf 'SHA-256: %s\n' "$(sha256sum "/proc/$pid/exe" 2>/dev/null | cut -c1-64)"
    if command -v dpkg >/dev/null; then
        local pk; alt_path "$ex"
        pk=$(dpkg -S "$ex" 2>/dev/null | head -1)
        [[ -z $pk && -n $ALT ]] && pk=$(dpkg -S "$ALT" 2>/dev/null | head -1)
        printf 'Package: %s\n' "${pk:-NOT OWNED BY ANY PACKAGE}"
    fi
    echo
    echo "--- parent chain ---"
    p=${P_PPID[i]}; d=0
    while [[ -n $p && $p -gt 0 && $d -lt 8 ]]; do
        j=${PIDX[$p]}
        [[ -n $j ]] && printf '  %s  %s  %s\n' "$p" "${P_USR[j]}" "$(tr -c '[:print:]' ' ' <<<"${P_CMD[j]:0:100}")"
        p=${PPIDOF[$p]}; ((d++))
    done
    echo
    echo "--- persistence entries that launch this exe ---"
    d=0
    for j in "${!K_TYPE[@]}"; do
        [[ " ${K_PID[j]}" == *" $pid "* ]] && { printf '  [%s] %s:%s  %s\n' "${K_TYPE[j]}" "${K_FILE[j]}" "${K_LINE[j]}" "${K_TXT[j]:0:100}"; d=1; }
    done
    ((d)) || echo "  none found"
    echo
    echo "--- open files / sockets (first 40) ---"
    for p in /proc/$pid/fd/*; do readlink "$p" 2>/dev/null; done | head -40
    echo
    echo "--- listening sockets ---"
    ss -tulpnH 2>/dev/null | grep "pid=$pid," || echo "  none"
}

inspect_pk() {
    local j=$1 f=${K_FILE[$1]} n=${K_LINE[$1]} s e u
    printf 'Type   : %s    Who: %s\n' "${K_TYPE[j]}" "${K_WHO[j]}"
    printf 'Level  : %s - %s\n' "${LVN[K_LVL[j]]}" "${K_WHY[j]}"
    printf 'File   : %s   Line: %s   State: %s\n' "$f" "$n" "${K_ST[j]:-active}"
    printf 'Launches running PID(s): %s\n' "${K_PID[j]:-none}"
    printf 'Backup : %s\n\n' "${K_BAK[j]:--}"
    printf 'Text   : %s\n\n' "${K_TXT[j]//[[:cntrl:]]/ }"
    if [[ $f == crontab:* ]]; then
        u=${f#crontab:}; echo "--- crontab -l -u $u ---"; crontab -l -u "$u" 2>/dev/null
    elif [[ -f $f ]]; then
        ls -l "$f"; command -v dpkg >/dev/null && { dpkg -S "$f" 2>/dev/null | head -1 || true; }
        echo
        if ((n > 0)); then
            s=$((n - 4)); ((s < 1)) && s=1; e=$((n + 4))
            echo "--- $f lines $s-$e ---"
            sed -n "${s},${e}p" "$f" 2>/dev/null | cut -c1-200 | cat -n
        else
            echo "--- $f (first 40 lines) ---"; head -n 40 "$f" 2>/dev/null | cut -c1-200
        fi
    fi
}

act_inspect() {
    ((${#VIEW[@]})) || return
    local t; t=$(mktemp) || return
    if [[ $TAB == P ]]; then inspect_proc "${VIEW[CUR]}" >"$t" 2>&1; else inspect_pk "${VIEW[CUR]}" >"$t" 2>&1; fi
    pager "$t"; rm -f "$t"
}

# ---------- report ----------
act_report() {
    local dir def out
    if [[ -n $SUDO_USER && -d /home/$SUDO_USER/Desktop ]]; then dir=/home/$SUDO_USER/Desktop
    elif [[ -n $SUDO_USER && -d /home/$SUDO_USER ]]; then dir=/home/$SUDO_USER
    else dir=/root; fi
    def=$dir/procwatch-report-$(date +%Y%m%d-%H%M).md
    prompt "Report path:" 0 "$def" || { ST="Cancelled"; SC=33; return; }
    out=$PVAL; [[ -z $out ]] && return
    if [[ -e $out ]]; then confirm "$out exists. Overwrite?" n || { ST="Cancelled"; SC=33; return; }; fi
    if ! write_report >"$out" 2>/dev/null; then ST="Cannot write $out"; SC=31; return; fi
    [[ -n $SUDO_USER ]] && chown "$SUDO_USER" "$out" 2>/dev/null
    REPN=${#A_TM[@]}
    log "report written: $out"
    ST="Report saved: $out"; SC=32
}

write_report() {
    local i j k n row pr ad po pd nm
    echo "# CyberPatriot Process & Persistence Report"
    echo
    printf -- '- **Host:** %s\n- **Date:** %s\n- **Operator:** %s\n- **Log:** `%s`\n- **Backups:** `%s`\n\n' "$(hostname)" "$(date '+%F %T')" "${SUDO_USER:-root}" "$LOGFILE" "$BAKDIR"
    echo "## Summary"
    echo
    echo "| Item | HIGH | MED | INFO |"
    echo "|---|---:|---:|---:|"
    echo "| Running processes | $NH | $NM | $NI |"
    echo "| Persistence entries (not yet disabled) | $QH | $QM | - |"
    echo
    echo "Actions taken this session: **${#A_TM[@]}**. Listening sockets: **${#LISTEN[@]}**."
    echo
    echo "## Actions taken"
    echo
    if ((${#A_TM[@]} == 0)); then echo "_None._"; else
        echo "| Time | Action | Target | User | Exe | SHA-256 | Result |"
        echo "|---|---|---|---|---|---|---|"
        for k in "${!A_TM[@]}"; do
            md "${A_TGT[k]}"; local t=$MD; md "${A_EXE[k]}"
            echo "| ${A_TM[k]} | ${A_ACT[k]} | \`$t\` | ${A_USR[k]} | \`$MD\` | ${A_SHA[k]:0:16} | ${A_RES[k]} |"
        done
    fi
    echo
    echo "## Suspicious processes still running"
    echo
    n=0
    for i in "${ORD[@]}"; do
        ((P_KT[i] || P_LVL[i] < 2)) && continue
        ((n++ == 0)) && { echo "| Level | PID | User | Ports | Command | Why |"; echo "|---|---:|---|---|---|---|"; }
        md "${P_CMD[i]:0:100}"; local c=$MD; md "${P_WHY[i]}"
        echo "| ${LVN[P_LVL[i]]} | ${P_PID[i]} | ${P_USR[i]} | ${P_PORTS[i]:--} | \`$c\` | $MD |"
    done
    ((n)) || echo "_None._"
    echo
    echo "## Network services to check against the README"
    echo
    n=0
    for i in "${ORD[@]}"; do
        ((P_KT[i] || P_LVL[i] != 1)) && continue
        ((n++ == 0)) && { echo "| PID | User | Ports | Command |"; echo "|---:|---|---|---|"; }
        md "${P_CMD[i]:0:100}"
        echo "| ${P_PID[i]} | ${P_USR[i]} | ${P_PORTS[i]:--} | \`$MD\` |"
    done
    ((n)) || echo "_None._"
    echo
    echo "## Listening ports"
    echo
    if ((${#LISTEN[@]} == 0)); then echo "_None._"; else
        echo "| Proto | Address | Port | PID | Process |"
        echo "|---|---|---:|---:|---|"
        for row in "${LISTEN[@]}"; do
            IFS=$'\t' read -r pr ad po pd nm <<<"$row"
            md "$ad"; ad=$MD; md "$nm"
            echo "| $pr | $ad | $po | $pd | $MD |"
        done
    fi
    echo
    echo "## Persistence findings"
    echo
    n=0
    for j in "${KORD[@]}"; do
        ((K_LVL[j] < 1 && ${#K_ST[j]} == 0)) && continue
        ((n++ == 0)) && { echo "| Level | Type | Who | File:line | Text | State | Backup |"; echo "|---|---|---|---|---|---|---|"; }
        local fl=${K_FILE[j]}; ((K_LINE[j] > 0)) && fl+=":${K_LINE[j]}"
        md "$fl"; local f1=$MD; kdisp "$j"; md "$LT"; local tx=$MD; md "${K_BAK[j]:--}"
        echo "| ${LVN[K_LVL[j]]} | ${K_TYPE[j]} | ${K_WHO[j]} | \`$f1\` | \`${tx:0:90}\` | ${K_ST[j]:-active} | \`$MD\` |"
    done
    ((n)) || echo "_None._"
    echo
    echo "Disabled lines carry the prefix \`# procwatch-disabled: \`. Originals are in the backup folder; undo with \`u\` inside procwatch or copy the backup over the file."
    echo
    echo "## Allowlist (README-approved)"
    echo
    n=0
    for k in "${!ALLOW[@]}"; do md "$k"; echo "- \`$MD\`"; n=1; done
    ((n)) || echo "_Empty._"
}

# ---------- main ----------
main_loop() {
    local n k rt
    while :; do
        get_size
        n=${#VIEW[@]}
        draw
        rt=""; ((AUTO)) && [[ $TAB == P ]] && rt=5
        readkey $rt
        if [[ $KEY == NONE ]]; then
            if [[ -n $rt ]] && ((SECONDS - LASTREF >= 5)); then refresh_procs; fi
            continue
        fi
        ST=""; SC=32
        case $KEY in
            UP|k)   ((CUR > 0)) && ((CUR--)) ;;
            DOWN|j) ((CUR < n - 1)) && ((CUR++)) ;;
            PGUP)   CUR=$((CUR - LH + 1)); ((CUR < 0)) && CUR=0 ;;
            PGDN)   CUR=$((CUR + LH - 1)); ((CUR > n - 1)) && CUR=$((n - 1)) ;;
            HOME|g) CUR=0 ;;
            END|G)  CUR=$((n - 1)) ;;
            TAB)    if [[ $TAB == P ]]; then TAB=K; else TAB=P; fi
                    VIEW=() CUR=0 TOP=0; build_view "" ;;
            ' ')    if ((n)); then
                        mk_of "${VIEW[CUR]}"
                        if [[ -n ${MARK[$MKEY]} ]]; then unset "MARK[$MKEY]"; else MARK[$MKEY]=1; fi
                        ((CUR < n - 1)) && ((CUR++))
                    fi ;;
            a)      for k in "${VIEW[@]}"; do mk_of "$k"; MARK[$MKEY]=1; done ;;
            A)      MARK=() ;;
            ENTER|v) act_inspect ;;
            x)      act_kill 15 ;;
            X)      act_kill 9 ;;
            S)      act_stop ;;
            d)      act_disable ;;
            u)      act_undo ;;
            w)      act_allow ;;
            [1-4])  FLT=$KEY; CUR=0 TOP=0; build_view ""
                    ST="Filter $FLT: $(filter_name)"; SC=36 ;;
            '/')    if prompt "Filter text:" 0 "$FILTER"; then FILTER=$PVAL; build_view; fi ;;
            r)      if [[ $TAB == P ]]; then say "Refreshing..."; refresh_procs; ST="Refreshed: $NH high, $NM med"; SC=36
                    else rescan_persist; ST="Rescanned persistence"; SC=36; fi ;;
            s)      rescan_persist; ST="Rescanned persistence (disabled rows leave the list; backups stay in $BAKDIR)"; SC=36 ;;
            t)      AUTO=$((1 - AUTO)); ST="Auto-refresh $( ((AUTO)) && echo 'on (5s, Processes tab)' || echo off)"; SC=36 ;;
            L)      pager +G "$LOGFILE" ;;
            R)      act_report ;;
            '?')    show_help ;;
            ESC)    if [[ -n $FILTER ]]; then FILTER=""; build_view; fi ;;
            q|Q)    if ((${#A_TM[@]} > REPN)); then
                        confirm "Write report before quitting?" y && act_report
                    fi
                    return ;;
        esac
        clamp
    done
}

filter_name() {
    if [[ $TAB == P ]]; then
        case $FLT in 1) echo "suspicious (MED/HIGH)" ;; 2) echo "plus network services (INFO)" ;; 3) echo "listening on the network" ;; 4) echo "everything incl. kernel threads" ;; esac
    else
        case $FLT in 1) echo "suspicious (MED/HIGH)" ;; 4) echo "everything" ;; *) echo "non-stock entries" ;; esac
    fi
}

trap 'restore_term; exit 0' EXIT
trap 'exit 130' INT TERM
trap ':' WINCH

touch "$LOGFILE" 2>/dev/null && chmod 600 "$LOGFILE" 2>/dev/null
init_term
get_size
log "session start (invoked by ${SUDO_USER:-root})"
load_allow
say "Scanning processes..."
collect_procs
scan_persist
LASTREF=$SECONDS
TAB=P; build_view ""
ST="$NH high, $NM medium process(es); $QH high, $QM medium persistence item(s). ? for help"; SC=36
((NH + QH)) && SC=33
main_loop
log "session end"
