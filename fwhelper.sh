#!/usr/bin/env bash
# fwhelper.sh - keyboard-driven UFW firewall helper for CyberPatriot (Linux Mint 21)
# Pure bash + ufw/ss/systemctl (all preinstalled). Run with: sudo ./fwhelper.sh
# Tick the services the README allows, review the plan, approve. Press ? for keybinds.

LOGFILE=/var/log/fwhelper.log
BKROOT=/var/backups/fwhelper

if [[ $EUID -ne 0 ]]; then
    echo "fwhelper: must be run as root (try: sudo $0)" >&2
    exit 1
fi
if [[ ! -t 0 || ! -t 1 ]]; then
    echo "fwhelper: needs an interactive terminal" >&2
    exit 1
fi
for c in ufw ss systemctl stty cp mkdir date; do
    command -v "$c" >/dev/null || { echo "fwhelper: missing command: $c" >&2; exit 1; }
done

# ---------- glyphs ----------
if [[ ${LC_ALL:-${LC_CTYPE:-$LANG}} == *[Uu][Tt][Ff]* ]]; then
    HR='─' KUD='↑↓' UP_ARR='↑' DN_ARR='↓' SEP='·'
else
    HR='-' KUD='Up/Dn' UP_ARR='^' DN_ARR='v' SEP='|'
fi

# ---------- state ----------
# one row per candidate inbound rule (parallel arrays)
SPEC=() LABEL=() SRC=() INSEC=() OPEN=() RULE=() LISTEN=() WANT=() CPLX=()
LPORT=() LPROTO=() LPROC=()      # listening sockets (non-loopback)
CUSTOM=()                        # specs added with n
declare -A WANTMAP=()
STEP_D=() STEP_K=() STEP_A=() STEP_C=()
PG=() PGC=()
LTS=() LLV=() LMSG=()
UFW_ACTIVE=0 DEF_IN="" DEF_OUT=""
NADD=0 NDEL=0 NMOD=0
CUR=0 TOP=0 LH=10
ST="" SC=32
TOK=() FOUND=0 LASTERR="" PVAL="" KEY="" BK="" LOCKMSG="" MD=""
SESSION_START=$(date '+%F %T')
SAVED_STTY=""
SPEC_RE='^[0-9]+(:[0-9]+)?(,[0-9]+(:[0-9]+)?)*(/(tcp|udp))?$'
PROC_RE='"([^"]+)"'

# label|spec|insecure
CATALOG=(
    "SSH|22/tcp|0"            "FTP|21/tcp|1"             "Telnet|23/tcp|1"
    "SMTP|25/tcp|0"           "DNS|53|0"                 "HTTP|80/tcp|0"
    "HTTPS|443/tcp|0"         "POP3|110/tcp|0"           "IMAP|143/tcp|0"
    "IMAPS|993/tcp|0"         "POP3S|995/tcp|0"          "Samba|139,445/tcp|0"
    "Samba NetBIOS|137,138/udp|0" "CUPS|631/tcp|0"       "MySQL|3306/tcp|0"
    "PostgreSQL|5432/tcp|0"   "RDP|3389/tcp|1"           "VNC|5900/tcp|1"
)

# log LEVEL message...   (tab separated: time, level, message)
log() {
    local lv=$1; shift
    printf '%s\t%s\t%s\n' "$(date '+%F %T')" "$lv" "$*" >>"$LOGFILE" 2>/dev/null
}

# ufw in the C locale, never reading stdin (so it can never block on a prompt)
ufwq() { LC_ALL=C ufw "$@" </dev/null 2>&1; }

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
cleanup() {
    log END "session end"
    restore_term
    exit 0
}
get_size() {
    local r c
    read -r r c < <(stty size 2>/dev/null)
    LINES=${r:-24} COLUMNS=${c:-80}
    ((LINES < 10)) && LINES=10
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
                        IFS= read -rsn1 -t 0.05 rest   # trailing ~
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
tokenize() {  # split on spaces, honouring 'single quotes' (no eval) -> TOK
    TOK=()
    local s=$1 t="" q=0 c i
    for ((i = 0; i < ${#s}; i++)); do
        c=${s:i:1}
        if [[ $c == "'" ]]; then q=$((1 - q))
        elif [[ $c == ' ' && $q -eq 0 ]]; then
            if [[ -n $t ]]; then TOK+=("$t"); t=""; fi
        else t+=$c; fi
    done
    [[ -n $t ]] && TOK+=("$t")
}

spec_covers() {  # spec port proto -> does this ufw port spec include that socket?
    local s=$1 p=$2 pr=$3 ports proto="" item lo hi
    [[ $s =~ $SPEC_RE ]] || return 1
    ports=${s%%/*}
    [[ $s == */* ]] && proto=${s##*/}
    [[ -n $proto && $proto != "$pr" ]] && return 1
    local IFS=,
    for item in $ports; do
        if [[ $item == *:* ]]; then lo=${item%%:*} hi=${item##*:}; else lo=$item hi=$item; fi
        ((p >= 10#$lo && p <= 10#$hi)) && return 0
    done
    return 1
}

valid_spec() {  # port[,port][:range][/proto]; lists and ranges need a protocol
    local s=$1 ports item lo hi
    [[ $s =~ $SPEC_RE ]] || return 1
    ports=${s%%/*}
    if [[ $s != */* && ( $ports == *,* || $ports == *:* ) ]]; then return 1; fi
    local IFS=,
    for item in $ports; do
        if [[ $item == *:* ]]; then lo=${item%%:*} hi=${item##*:}; else lo=$item hi=$item; fi
        ((10#$lo >= 1 && 10#$hi <= 65535 && 10#$lo <= 10#$hi)) || return 1
    done
}

add_row() {  # label spec src insecure
    LABEL+=("$1") SPEC+=("$2") SRC+=("$3") INSEC+=("$4")
    OPEN+=("") RULE+=("") LISTEN+=("") WANT+=("") CPLX+=(0)
}

find_spec() {  # sets FOUND
    local i
    for i in "${!SPEC[@]}"; do
        if [[ ${SPEC[i]} == "$1" ]]; then FOUND=$i; return 0; fi
    done
    return 1
}

add_listen() {  # add_listen index "proc,proc"
    local p; local -a arr
    IFS=, read -ra arr <<<"$2"
    for p in "${arr[@]}"; do
        [[ ",${LISTEN[$1]}," == *",$p,"* ]] || LISTEN[$1]+="${LISTEN[$1]:+,}$p"
    done
}

# ---------- data ----------
ufw_state() {
    local out
    UFW_ACTIVE=0 DEF_IN="" DEF_OUT=""
    out=$(ufwq status verbose)
    [[ $out == *"Status: active"* ]] && UFW_ACTIVE=1
    if [[ $out =~ Default:\ ([a-z]+)\ \(incoming\),\ ([a-z]+)\ \(outgoing\) ]]; then
        DEF_IN=${BASH_REMATCH[1]} DEF_OUT=${BASH_REMATCH[2]}
    fi
}

load_state() {
    local ent label spec insec i k line action rest r2 n netid la proc addr port pn j m found
    SPEC=() LABEL=() SRC=() INSEC=() OPEN=() RULE=() LISTEN=() WANT=() CPLX=()
    LPORT=() LPROTO=() LPROC=()
    ufw_state

    for ent in "${CATALOG[@]}"; do
        IFS='|' read -r label spec insec <<<"$ent"
        add_row "$label" "$spec" catalog "$insec"
    done

    # existing user rules (works while ufw is inactive); only inbound allow/limit are managed
    while IFS= read -r line; do
        [[ $line == "ufw "* ]] || continue
        line=${line#ufw }
        action=${line%% *} rest=${line#* }
        case $action in allow|limit) ;; *) continue ;; esac
        [[ $rest == "out "* ]] && continue
        r2=$rest; [[ $r2 == "in "* ]] && r2=${r2#in }
        if [[ $r2 =~ $SPEC_RE ]] && find_spec "$r2" && [[ -z ${OPEN[FOUND]} ]]; then
            OPEN[FOUND]=$action RULE[FOUND]="$action $rest"
        else
            tokenize "$r2"
            if ((${#TOK[@]} == 1)) && [[ ${TOK[0]} != [0-9]* ]]; then add_row "app profile" "${TOK[0]}" rule 0
            else add_row "custom rule" "$r2" rule 0; fi
            n=$((${#SPEC[@]} - 1))
            OPEN[n]=$action RULE[n]="$action $rest" CPLX[n]=1
        fi
    done < <(ufwq show added)

    for spec in "${CUSTOM[@]}"; do
        find_spec "$spec" || add_row "custom" "$spec" custom 0
    done

    # listening sockets (skip loopback)
    while read -r netid _ _ _ la _ proc; do
        [[ $netid == tcp || $netid == udp ]] || continue
        port=${la##*:} addr=${la%:*}
        case $addr in 127.*|'[::1]'|::1) continue ;; esac
        [[ $port =~ ^[0-9]+$ ]] || continue
        pn="?"; [[ $proc =~ $PROC_RE ]] && pn=${BASH_REMATCH[1]}
        found=0
        for j in "${!LPORT[@]}"; do
            if [[ ${LPORT[j]} == "$port" && ${LPROTO[j]} == "$netid" ]]; then
                [[ ",${LPROC[j]}," == *",$pn,"* ]] || LPROC[j]+=",$pn"
                found=1; break
            fi
        done
        ((found)) || { LPORT+=("$port"); LPROTO+=("$netid"); LPROC+=("$pn"); }
    done < <(ss -Hlntup 2>/dev/null)

    for j in "${!LPORT[@]}"; do
        m=0
        for i in "${!SPEC[@]}"; do
            ((CPLX[i])) && continue
            if spec_covers "${SPEC[i]}" "${LPORT[j]}" "${LPROTO[j]}"; then add_listen "$i" "${LPROC[j]}"; m=1; fi
        done
        if ((!m)); then
            add_row "listen: ${LPROC[j]}" "${LPORT[j]}/${LPROTO[j]}" listen 0
            LISTEN[${#SPEC[@]} - 1]=${LPROC[j]}
        fi
    done

    for i in "${!SPEC[@]}"; do
        k=${SPEC[i]}
        if [[ -n ${WANTMAP[$k]+set} ]]; then WANT[i]=${WANTMAP[$k]}; else WANT[i]=${OPEN[i]}; fi
    done
}

reload() {  # reload [keep ticks=1]
    local keep=${1:-1} i cs=""
    ((${#SPEC[@]})) && cs=${SPEC[CUR]}
    WANTMAP=()
    if ((keep)); then for i in "${!SPEC[@]}"; do WANTMAP["${SPEC[i]}"]=${WANT[i]}; done; fi
    load_state
    CUR=0
    if [[ -n $cs ]]; then
        for i in "${!SPEC[@]}"; do [[ ${SPEC[i]} == "$cs" ]] && { CUR=$i; break; }; done
    fi
    clamp
}

count_changes() {
    local i
    NADD=0 NDEL=0 NMOD=0
    for i in "${!SPEC[@]}"; do
        [[ ${WANT[i]} == "${OPEN[i]}" ]] && continue
        if [[ -z ${OPEN[i]} ]]; then ((NADD++))
        elif [[ -z ${WANT[i]} ]]; then ((NDEL++))
        else ((NMOD++)); fi
    done
}

clamp() {
    local n=${#SPEC[@]}
    ((CUR >= n)) && CUR=$((n - 1))
    ((CUR < 0)) && CUR=0
    ((CUR < TOP)) && TOP=$CUR
    ((CUR >= TOP + LH)) && TOP=$((CUR - LH + 1))
    ((TOP < 0)) && TOP=0
}

# ---------- drawing ----------
draw() {
    local W=$COLUMNS i row idx buf part n=${#SPEC[@]}
    if ((W < 68)); then printf '\e[H\e[J fwhelper: terminal too narrow (need 68 columns)'; return; fi
    LH=$((LINES - 6)); ((LH < 1)) && LH=1
    clamp
    count_changes

    local st stc left=" CyberPatriot Firewall" rplain rcol sp
    if ((UFW_ACTIVE)); then st="UFW ACTIVE" stc=$'\e[1;92m'; else st="UFW INACTIVE" stc=$'\e[1;91m'; fi
    rplain=" $st $SEP in:${DEF_IN:--} $SEP +$NADD -$NDEL ~$NMOD "
    rcol=" ${stc}${st}"$'\e[1;97m'" $SEP in:${DEF_IN:--} $SEP +$NADD -$NDEL ~$NMOD "
    printf -v sp '%*s' $((W - ${#left} - ${#rplain} > 0 ? W - ${#left} - ${#rplain} : 1)) ''
    buf=$'\e[H\e[1;97;44m'"${left}${sp}${rcol}"$'\e[0m\e[K\n'

    local hdr
    printf -v hdr ' %-4s%-15s %-12s %-10s %-12s %s' '' SERVICE PORTS NOW LISTENING CHANGE
    buf+=$'\e[1;36m'"${hdr:0:W}"$'\e[0m\e[K\n'

    local tailw=$((W - 58))
    for ((row = 0; row < LH; row++)); do
        idx=$((TOP + row))
        if ((idx >= n)); then buf+=$'\e[K\n'; continue; fi
        local base=$'\e[39m' pre="" sel=0 dim=$'\e[90m'
        ((idx == CUR)) && { sel=1; pre=$'\e[48;5;24m\e[97m'; base=$'\e[97m'; dim=$'\e[37m'; }

        local mk="[ ]" mkc=""
        case ${WANT[idx]} in
            allow) mk="[x]" mkc=$'\e[92m' ;;
            limit) mk="[L]" mkc=$'\e[93m' ;;
        esac

        local lab_c=""; [[ ${INSEC[idx]} == 1 ]] && lab_c=$'\e[93m'

        local now now_c
        if ((!UFW_ACTIVE)); then now="unenforced" now_c=$'\e[33m'
        elif [[ -n ${OPEN[idx]} ]]; then
            now=${OPEN[idx]}; now_c=$'\e[92m'; [[ $now == limit ]] && now_c=$'\e[93m'
        else now="closed" now_c=$dim; fi

        local lis=${LISTEN[idx]} lis_c=""
        if [[ -n $lis ]]; then
            if [[ -n ${WANT[idx]} ]]; then lis_c=$'\e[92m'; else lis_c=$'\e[91m'; fi
        fi

        local chg="" chg_c=""
        if [[ ${WANT[idx]} != "${OPEN[idx]}" ]]; then
            if [[ -z ${OPEN[idx]} ]]; then chg="+ ${WANT[idx]}" chg_c=$'\e[92m'
            elif [[ -z ${WANT[idx]} ]]; then chg="- close" chg_c=$'\e[91m'
            else chg="~ ${WANT[idx]}" chg_c=$'\e[93m'; fi
        elif [[ ${INSEC[idx]} == 1 && -n ${WANT[idx]} ]]; then
            chg="insecure!" chg_c=$'\e[93m'
        fi

        local line="$pre$base "
        printf -v part '%s' "$mk"; line+="$mkc$part$base "
        printf -v part '%-15.15s ' "${LABEL[idx]}"; line+="$lab_c$part$base"
        printf -v part '%-12.12s ' "${SPEC[idx]}"; line+="$part"
        printf -v part '%-10s ' "$now"; line+="$now_c$part$base"
        printf -v part '%-12.12s ' "$lis"; line+="$lis_c$part$base"
        printf -v part '%-*.*s' "$tailw" "$tailw" "$chg"; line+="$chg_c$part"
        buf+="$line"$'\e[0m\e[K\n'
    done

    local info=""
    ((TOP > 0)) && info+=" $UP_ARR more "
    ((TOP + LH < n)) && info+=" $DN_ARR more "
    local rule; printf -v rule '%*s' $((W - ${#info})) ''
    buf+=$'\e[2m'"${rule// /$HR}${info}"$'\e[0m\e[K\n'

    # status line: last message, else details of the highlighted row
    local msg=$ST sc=$SC
    if [[ -z $msg && $n -gt 0 ]]; then
        sc=37
        msg="${LABEL[CUR]}: ${SPEC[CUR]}"
        [[ -n ${RULE[CUR]} ]] && msg+=" | ufw ${RULE[CUR]}"
        [[ -n ${LISTEN[CUR]} ]] && msg+=" | listening: ${LISTEN[CUR]}"
        [[ ${INSEC[CUR]} == 1 ]] && msg+=" | INSECURE protocol"
    fi
    buf+=$'\e['"$sc"'m '"${msg:0:W-2}"$'\e[0m\e[K\n'

    local -a hints=("$KUD:move" "Spc:allow" "l:limit" "n:new" "Ret:apply" "a:all" "A:none"
                    "d:del" "v:status" "b:restore" "e:export" "?:help" "q:quit")
    local h kk ll len piece hl0=" " hl1=" " cl=0 used=1
    for h in "${hints[@]}"; do
        kk=${h%%:*} ll=${h#*:}; len=$((${#kk} + ${#ll} + 3))
        if ((cl == 0 && used + len > W)); then cl=1; used=1; fi
        if ((cl == 1 && used + len > W)); then break; fi
        piece=$'\e[1;36m'"$kk"$'\e[0m\e[90m'" $ll  "$'\e[0m'
        if ((cl == 0)); then hl0+=$piece; else hl1+=$piece; fi
        ((used += len))
    done
    buf+="$hl0"$'\e[K\n'"$hl1"$'\e[K\e[J'
    printf '%s' "$buf"
}

show_help() {
    local lines=(
        "KEYBINDS"
        ""
        "  Up/Down  j/k       move                PgUp/PgDn  Home/End  g/G   jump"
        "  Space              allow / don't allow the row   (the README decides!)"
        "  l                  rate-limit instead of plain allow (good for SSH)"
        "  a  tick all        A  untick all"
        "  n                  add a custom port, e.g. 8080/tcp or 6000:6010/tcp"
        "  d  Del             remove a custom row you added with n"
        "  Enter              review the plan, then approve to apply"
        "  v                  raw 'ufw status verbose' and user rules"
        "  b                  restore the newest /etc/ufw backup (current state saved first)"
        "  e                  export Markdown report (this session's changes)"
        "  E                  export Markdown report (entire log history)"
        "  r                  reload from ufw (keeps your ticks)      q  quit"
        ""
        "How it works"
        "  Ticked rows get allowed; rows that are open but NOT ticked get deleted."
        "  Default policy becomes deny incoming / allow outgoing, ufw is enabled."
        "  Nothing runs until you approve the preview. /etc/ufw is backed up first."
        ""
        "Colours"
        "  LISTENING red   = a process listens there but UFW will not allow it"
        "  NOW unenforced  = ufw is INACTIVE, so no rule is actually protecting anything"
        "  yellow service  = insecure protocol (telnet, ftp, rdp, vnc)"
        ""
        "Log:    $LOGFILE"
        "Backup: $BKROOT"
        "Report: Desktop of \$SUDO_USER (else their home, else /root)"
        ""
        "  press any key"
    )
    local buf=$'\e[H\e[J\e[1;97;44m' sp
    printf -v sp '%*s' "$COLUMNS" ''
    buf+=" Help${sp:5}"$'\e[0m\n\n'
    local l; for l in "${lines[@]}"; do buf+="$l"$'\n'; done
    printf '%s' "$buf"
    readkey
}

# Scrollable viewer over PG/PGC. ask=1: returns 0 only if y is pressed.
pager() {  # pager "title" "sgr bg" [ask]
    local t=0 n lh r idx buf sp ttl=" $1" ask=${3:-0} hint
    while :; do
        get_size
        n=${#PG[@]}
        lh=$((LINES - 2)); ((lh < 1)) && lh=1
        ((t > n - lh)) && t=$((n - lh))
        ((t < 0)) && t=0
        printf -v sp '%*s' $((COLUMNS - ${#ttl} > 0 ? COLUMNS - ${#ttl} : 0)) ''
        buf=$'\e[H\e['"$2"'m'"${ttl}${sp}"$'\e[0m\e[K\n'
        for ((r = 0; r < lh; r++)); do
            idx=$((t + r))
            if ((idx >= n)); then buf+=$'\e[K\n'; continue; fi
            buf+="${PGC[idx]}${PG[idx]:0:COLUMNS-1}"$'\e[0m\e[K\n'
        done
        hint=$'\e[1;36m '"$KUD"$'\e[0m\e[90m scroll  \e[0m'
        if ((ask)); then hint+=$'\e[1;92my\e[0m\e[90m apply  \e[0m\e[1;36mEsc\e[0m\e[90m cancel\e[0m'
        else hint+=$'\e[1;36mEsc\e[0m\e[90m back\e[0m'; fi
        buf+="$hint"$'\e[K\e[J'
        printf '%s' "$buf"
        readkey
        case $KEY in
            UP|k)   ((t > 0)) && ((t--)) ;;
            DOWN|j) ((t++)) ;;
            PGUP)   t=$((t - lh)) ;;
            PGDN)   t=$((t + lh)) ;;
            HOME|g) t=0 ;;
            END|G)  t=$n ;;
            y|Y)    if ((ask)); then return 0; fi ;;
            ESC|q|Q|n|N) return 1 ;;
        esac
    done
}

pg() { PGC+=("$1"); PG+=("$2"); }

# ---------- prompts ----------
prompt() {   # prompt "label" -> PVAL ; returns 1 on Esc
    local label=$1 s=""
    printf '\e[?25h'
    while :; do
        printf '\e[%d;1H\e[K\e[1;36m %s\e[0m %s' "$LINES" "$label" "$s"
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
    return 0
}

confirm() {  # confirm "question" [default y|n]
    local def=${2:-n} hint='[y/N]'
    [[ $def == y ]] && hint='[Y/n]'
    printf '\e[%d;1H\e[K\e[1;33m %s %s\e[0m' "$LINES" "${1:0:$((COLUMNS - 10))}" "$hint"
    while :; do
        readkey
        case $KEY in
            y|Y) return 0 ;;
            n|N|ESC) return 1 ;;
            ENTER) [[ $def == y ]]; return ;;
        esac
    done
}

# ---------- actions ----------
run() {  # run "description" cmd args...   (stdin closed, output captured, result logged)
    local d=$1 o rc; shift
    o=$("$@" 2>&1 </dev/null); rc=$?
    if ((rc == 0)); then log OK "$d"; LASTERR=""; return 0; fi
    log FAIL "($rc) $d: ${o//$'\n'/ }"
    LASTERR=${o//$'\n'/ }
    return $rc
}

act_toggle() {
    local want
    if ((CPLX[CUR])); then
        if [[ -n ${WANT[CUR]} ]]; then want=""; else want=${OPEN[CUR]:-allow}; fi
    else
        if [[ -n ${WANT[CUR]} ]]; then want=""; else want=allow; fi
    fi
    WANT[CUR]=$want
    ((CUR < ${#SPEC[@]} - 1)) && ((CUR++))
}

act_limit() {
    if ((CPLX[CUR])); then ST="Custom rules can only be kept or removed"; SC=33; return; fi
    if [[ ${WANT[CUR]} == limit ]]; then WANT[CUR]=allow; else WANT[CUR]=limit; fi
}

act_all() {
    confirm "Tick ALL services (including insecure ones)?" n || return
    local i
    for i in "${!SPEC[@]}"; do ((CPLX[i])) || [[ -n ${WANT[i]} ]] || WANT[i]=allow; done
}

act_none() { local i; for i in "${!SPEC[@]}"; do WANT[i]=""; done; }

act_new() {
    local s
    prompt "Port[/proto] (e.g. 8080/tcp, 6000:6010/tcp):" || { ST="Cancelled"; SC=33; return; }
    s=$PVAL
    if ! valid_spec "$s"; then ST="Invalid '$s' (ports 1-65535; lists/ranges need /tcp or /udp)"; SC=31; return; fi
    if find_spec "$s"; then
        CUR=$FOUND; [[ -z ${WANT[FOUND]} ]] && WANT[FOUND]=allow
        ST="$s is already listed - ticked"; SC=36; return
    fi
    add_row "custom" "$s" custom 0
    CUSTOM+=("$s")
    CUR=$((${#SPEC[@]} - 1)); WANT[CUR]=allow
    ST="Added $s (ticked)"; SC=32
}

act_del() {
    if [[ ${SRC[CUR]} != custom ]]; then ST="Only rows added with n can be removed (untick instead)"; SC=33; return; fi
    local s=${SPEC[CUR]} keep=() c
    for c in "${CUSTOM[@]}"; do [[ $c == "$s" ]] || keep+=("$c"); done
    CUSTOM=("${keep[@]}")
    reload
    ST="Removed $s"; SC=36
}

act_status() {
    local l
    PG=() PGC=()
    pg $'\e[1m' "ufw status verbose"
    while IFS= read -r l; do pg "" "  $l"; done < <(ufwq status verbose)
    pg "" ""
    pg $'\e[1m' "User rules (ufw show added)"
    while IFS= read -r l; do pg "" "  $l"; done < <(ufwq show added)
    pg "" ""
    pg $'\e[1m' "Listening (non-loopback)"
    local j
    for j in "${!LPORT[@]}"; do pg "" "  ${LPORT[j]}/${LPROTO[j]}  ${LPROC[j]}"; done
    pager "Firewall status" "1;97;44"
}

# ---------- apply ----------
add_step() {  # glyph desc kind args
    STEP_C+=("$1") STEP_D+=("$2") STEP_K+=("$3") STEP_A+=("$4")
}

build_plan() {
    STEP_D=() STEP_K=() STEP_A=() STEP_C=()
    local i n=${#SPEC[@]}
    for ((i = 0; i < n; i++)); do   # adds first, so a swap never leaves a gap
        [[ -n ${WANT[i]} && ${WANT[i]} != "${OPEN[i]}" ]] || continue
        ((CPLX[i])) && continue
        add_step "+" "${WANT[i]} ${SPEC[i]}   (${LABEL[i]})" ufw "${WANT[i]} ${SPEC[i]}"
    done
    for ((i = 0; i < n; i++)); do
        [[ -n ${OPEN[i]} && ${WANT[i]} != "${OPEN[i]}" ]] || continue
        add_step "-" "delete ${RULE[i]}" ufw "delete ${RULE[i]}"
    done
    [[ $DEF_IN == deny ]]   || add_step "*" "default deny incoming" ufw "default deny incoming"
    [[ $DEF_OUT == allow ]] || add_step "*" "default allow outgoing" ufw "default allow outgoing"
    ((UFW_ACTIVE)) || add_step "*" "enable firewall" ufw "--force enable"
    [[ $(systemctl is-enabled ufw 2>/dev/null) == enabled ]] || add_step "*" "enable ufw at boot" systemctl "enable ufw"
    if ((${#STEP_D[@]})); then   # backup goes first
        STEP_C=("*" "${STEP_C[@]}")
        STEP_D=("back up /etc/ufw to $BKROOT" "${STEP_D[@]}")
        STEP_K=(backup "${STEP_K[@]}")
        STEP_A=("" "${STEP_A[@]}")
    fi
}

bk_copy() {
    mkdir -p "$1/etc-ufw" && chmod 700 "$BKROOT" &&
        cp -a /etc/ufw/. "$1/etc-ufw/" && cp -a /etc/default/ufw "$1/default-ufw"
}
bk_restore() { cp -a "$1/etc-ufw/." /etc/ufw/ && cp -a "$1/default-ufw" /etc/default/ufw; }

do_backup() {
    BK=$BKROOT/ufw-$(date +%Y%m%d-%H%M%S)
    run "backup /etc/ufw -> $BK" bk_copy "$BK"
}

exec_step() {
    case ${STEP_K[$1]} in
        backup)    do_backup ;;
        ufw)       tokenize "${STEP_A[$1]}"; run "ufw ${STEP_A[$1]}" ufwq "${TOK[@]}" ;;
        systemctl) tokenize "${STEP_A[$1]}"; run "systemctl ${STEP_A[$1]}" systemctl "${TOK[@]}" ;;
    esac
}

# Would an sshd port that has a live session be left without an allow rule?
lockout_risk() {
    LOCKMSG=""
    local j i p la ok
    local -a sshp=()
    for j in "${!LPORT[@]}"; do
        [[ ${LPROTO[j]} == tcp && ",${LPROC[j]}," == *",sshd,"* ]] && sshp+=("${LPORT[j]}")
    done
    ((${#sshp[@]})) || return 1
    while read -r _ _ la _; do
        p=${la##*:}
        for j in "${sshp[@]}"; do
            [[ $p == "$j" ]] || continue
            ok=0
            for i in "${!SPEC[@]}"; do
                [[ -n ${WANT[i]} ]] || continue
                if spec_covers "${SPEC[i]}" "$p" tcp; then ok=1; break; fi
                if ((CPLX[i])) && [[ ${SPEC[i]} == *"$p"* ]]; then ok=1; break; fi
            done
            if ((!ok)); then LOCKMSG="SSH port $p has a live session and is NOT ticked: you could not reconnect."; return 0; fi
        done
    done < <(ss -Hnt state established 2>/dev/null)
    return 1
}

act_apply() {
    build_plan
    local ns=${#STEP_D[@]} s l col lock=0
    if ((ns == 0)); then ST="Nothing to change - firewall already matches your ticks"; SC=36; return; fi

    PG=() PGC=()
    pg $'\e[1m' "Current firewall"
    while IFS= read -r l; do pg $'\e[2m' "  $l"; done < <(ufwq status verbose)
    pg "" ""
    pg $'\e[1m' "Planned changes ($ns steps)"
    for ((s = 0; s < ns; s++)); do
        case ${STEP_C[s]} in
            +) col=$'\e[92m' ;; -) col=$'\e[91m' ;; *) col=$'\e[36m' ;;
        esac
        pg "$col" "  ${STEP_C[s]} ${STEP_D[s]}"
    done
    if lockout_risk; then
        lock=1
        pg "" ""
        pg $'\e[1;91m' "  WARNING: $LOCKMSG"
    fi
    pager "Review changes - nothing has been applied yet" "1;97;41" 1 || { ST="Cancelled - nothing changed"; SC=33; return; }
    if ((lock)); then
        confirm "$LOCKMSG Apply anyway?" n || { ST="Cancelled - nothing changed"; SC=33; return; }
    fi

    local ok=0 fail=0 aborted=0
    BK=""
    for ((s = 0; s < ns; s++)); do
        printf '\e[%d;1H\e[K\e[36m [%d/%d] %s\e[0m' "$LINES" $((s + 1)) "$ns" "${STEP_D[s]:0:$((COLUMNS - 16))}"
        if exec_step "$s"; then ((ok++))
        else
            ((fail++))
            confirm "Step failed: ${LASTERR:0:45} - continue?" n || { aborted=1; break; }
        fi
    done
    reload 0
    if ((fail)); then ST="Applied $ok, $fail failed$( ((aborted)) && echo ' (stopped)'): $LASTERR"; SC=31
    else ST="Applied $ok steps (0 failed)${BK:+. Backup: $BK}"; SC=32; fi
}

act_restore() {
    local -a d=("$BKROOT"/ufw-*/)
    local t=${d[${#d[@]} - 1]}
    t=${t%/}
    if [[ ! -d $t ]]; then ST="No backups in $BKROOT"; SC=33; return; fi
    confirm "Restore /etc/ufw from ${t##*/}? (current state is backed up first)" n || { ST="Cancelled"; SC=33; return; }
    do_backup || { ST="Backup failed, not restoring: $LASTERR"; SC=31; return; }
    if run "restore /etc/ufw <- $t" bk_restore "$t"; then
        run "ufw reload" ufwq reload
        ST="Restored ${t##*/} (previous state saved to ${BK##*/})"; SC=32
    else
        ST="Restore failed: $LASTERR"; SC=31
    fi
    reload 0
}

# ---------- markdown report ----------
collect_log() {  # collect_log session|full -> LTS LLV LMSG (OK/FAIL only)
    LTS=() LLV=() LMSG=()
    local ts lv msg
    [[ -r $LOGFILE ]] || return
    while IFS=$'\t' read -r ts lv msg; do
        if [[ $lv == START && $1 == session ]]; then LTS=() LLV=() LMSG=(); fi
        case $lv in OK|FAIL) LTS+=("$ts") LLV+=("$lv") LMSG+=("$msg") ;; esac
    done <"$LOGFILE"
}

md_esc() { MD=${1//|/\\|}; }

act_export() {  # act_export session|full
    local mode=$1 home="" dir f stamp i j osname l state covered
    if [[ -n $SUDO_USER && $SUDO_USER != root ]]; then
        IFS=: read -r _ _ _ _ _ home _ < <(getent passwd "$SUDO_USER")
    fi
    [[ -z $home || ! -d $home ]] && home=/root
    dir=$home; [[ -d $home/Desktop ]] && dir=$home/Desktop
    stamp=$(date '+%Y%m%d-%H%M%S')
    f=$dir/fwhelper-report-$stamp.md
    osname=$( . /etc/os-release 2>/dev/null; printf '%s' "${PRETTY_NAME:-unknown}" )
    ufw_state
    collect_log "$mode"

    {
        printf '# CyberPatriot Firewall Report\n\n'
        printf -- '- **Host:** %s\n- **OS:** %s\n- **Generated:** %s\n- **Operator:** %s\n' \
            "${HOSTNAME:-?}" "$osname" "$(date '+%F %T')" "${SUDO_USER:-root}"
        if [[ $mode == session ]]; then printf -- '- **Scope:** this session (started %s)\n' "$SESSION_START"
        else printf -- '- **Scope:** full log history (%s)\n' "$LOGFILE"; fi
        printf -- '- **UFW:** %s, default incoming: %s, outgoing: %s\n\n' \
            "$( ((UFW_ACTIVE)) && echo active || echo INACTIVE )" "${DEF_IN:-n/a}" "${DEF_OUT:-n/a}"

        printf '## Changes\n\n'
        if ((${#LMSG[@]} == 0)); then
            printf '_No changes recorded._\n\n'
        else
            printf '| Time | Result | Action |\n|---|---|---|\n'
            for i in "${!LMSG[@]}"; do
                md_esc "${LMSG[i]}"
                printf '| %s | %s | `%s` |\n' "${LTS[i]}" "${LLV[i]}" "$MD"
            done
            printf '\n'
        fi

        printf '## Allowed services (current)\n\n'
        state=0
        for i in "${!SPEC[@]}"; do [[ -n ${OPEN[i]} ]] && state=1; done
        if ((!state)); then
            printf '_No inbound allow rules._\n\n'
        else
            printf '| Service | Ports | Action | Listening |\n|---|---|---|---|\n'
            for i in "${!SPEC[@]}"; do
                [[ -n ${OPEN[i]} ]] || continue
                md_esc "${SPEC[i]}"
                printf '| %s | `%s` | %s | %s |\n' "${LABEL[i]}" "$MD" "${OPEN[i]}" "${LISTEN[i]:--}"
            done
            printf '\n'
        fi

        printf '## Listening ports (current)\n\n'
        if ((${#LPORT[@]} == 0)); then
            printf '_None (besides loopback)._\n\n'
        else
            printf '| Port | Process | Status |\n|---|---|---|\n'
            for j in "${!LPORT[@]}"; do
                covered=0
                for i in "${!SPEC[@]}"; do
                    [[ -n ${OPEN[i]} ]] || continue
                    if spec_covers "${SPEC[i]}" "${LPORT[j]}" "${LPROTO[j]}"; then covered=1; break; fi
                done
                if ((!UFW_ACTIVE)); then state="exposed (UFW inactive)"
                elif ((covered)); then state="allowed"
                elif [[ $DEF_IN == deny ]]; then state="blocked"
                else state="exposed (default allow)"; fi
                printf '| %s/%s | %s | %s |\n' "${LPORT[j]}" "${LPROTO[j]}" "${LPROC[j]}" "$state"
            done
            printf '\n'
        fi

        printf '## Backups made\n\n'
        state=0
        for i in "${!LMSG[@]}"; do
            if [[ ${LLV[i]} == OK && ${LMSG[i]} == "backup /etc/ufw -> "* ]]; then
                printf -- '- `%s` (%s)\n' "${LMSG[i]#backup /etc/ufw -> }" "${LTS[i]}"; state=1
            fi
        done
        ((state)) || printf '_None in this scope._\n'

        printf '\n## ufw status verbose\n\n```\n'
        while IFS= read -r l; do printf '%s\n' "$l"; done < <(ufwq status verbose)
        printf '```\n'
    } >"$f" 2>/dev/null

    if [[ -s $f ]]; then
        [[ -n $SUDO_USER && $SUDO_USER != root ]] && chown "$SUDO_USER" "$f" 2>/dev/null
        chmod 600 "$f" 2>/dev/null
        log OK "exported report $f ($mode)"
        ST="Report written: $f"; SC=32
    else
        ST="Could not write report to $dir"; SC=31
    fi
}

# ---------- main ----------
main_loop() {
    local n
    while :; do
        get_size
        n=${#SPEC[@]}
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
            ' ')    act_toggle ;;
            l)      act_limit ;;
            a)      act_all ;;
            A)      act_none ;;
            n)      act_new ;;
            d|DEL)  act_del ;;
            ENTER)  act_apply ;;
            v)      act_status ;;
            b)      act_restore ;;
            e)      act_export session ;;
            E)      act_export full ;;
            r)      reload; ST="Reloaded from ufw"; SC=36 ;;
            '?'|h)  show_help ;;
            q|Q)    count_changes
                    if ((NADD + NDEL + NMOD == 0)) || confirm "Unapplied changes. Quit anyway?" n; then return; fi ;;
        esac
        clamp
    done
}

trap cleanup EXIT
trap 'exit 130' INT TERM
trap ':' WINCH

touch "$LOGFILE" 2>/dev/null && chmod 600 "$LOGFILE" 2>/dev/null
init_term
get_size
reload 0
log START "session start (invoked by ${SUDO_USER:-root})"
((UFW_ACTIVE)) || log FIND "ufw is INACTIVE"
[[ -n $DEF_IN && $DEF_IN != deny ]] && log FIND "default incoming policy is $DEF_IN"
for i in "${!SPEC[@]}"; do
    [[ -n ${LISTEN[i]} && -z ${OPEN[i]} ]] && log FIND "${SPEC[i]} (${LISTEN[i]}) is listening with no allow rule"
done
main_loop
