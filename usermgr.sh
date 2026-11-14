#!/usr/bin/env bash
# usermgr.sh - keyboard-driven local user manager for CyberPatriot (Linux Mint 21)
# Pure bash + shadow-utils. Run with: sudo ./usermgr.sh
# Press ? inside for keybinds.

LOGFILE=/var/log/usermgr.log

if [[ $EUID -ne 0 ]]; then
    echo "usermgr: must be run as root (try: sudo $0)" >&2
    exit 1
fi
if [[ ! -t 0 || ! -t 1 ]]; then
    echo "usermgr: needs an interactive terminal" >&2
    exit 1
fi
for c in getent useradd userdel usermod gpasswd chpasswd passwd chage lastlog stty sort; do
    command -v "$c" >/dev/null || { echo "usermgr: missing command: $c" >&2; exit 1; }
done

# ---------- glyphs ----------
if [[ ${LC_ALL:-${LC_CTYPE:-$LANG}} == *[Uu][Tt][Ff]* ]]; then
    HR='─' MK='●' KUD='↑↓' UP_ARR='↑' DN_ARR='↓' SEP='·' ISS='⚠'
else
    HR='-' MK='*' KUD='Up/Dn' UP_ARR='^' DN_ARR='v' SEP='|' ISS='!'
fi

# ---------- state ----------
NAMES=() UIDS=() GIDS=() HOMES=() SHELLS=()
declare -A SUDOER=() PWF=() LASTCHG=() LASTLOG=() FLAGS=() MARK=()
declare -A PWPLAIN=() PWHASH=()   # passwords set by this tool, used only for LEN (memory only, never logged)
declare -A PWST=()                # passwd -S status code per user: P / L / NP
SHOWPW=1 SHOWLEN=0 SHOWAGE=1 SHOWPOL=1 PWMIN=12
ONOFF=(off ON)
SCOPE_MSG=('Showing regular users + flagged' 'Showing ALL accounts')
declare -A SHMAX=() SHEXP=()      # shadow max-age and account-expiry fields (days)
POL_AGE="" POL_AGE_BAD=0 POL_PQ="" POL_PQ_BAD=0
TODAY=0
NFLAG=0
VIEW=()                 # indices into NAMES currently displayed
CUR=0 TOP=0 LH=10
FILTER="" SHOWALL=0
ST="" SC=32             # status text / colour
UID_MIN=1000 UID_MAX=60000
KEY="" PVAL="" TG=() LASTERR="" JUMP="" REASON=""
R_ROLE="" R_ROLEC="" R_STATE="" R_STATEC=""
LTS=() LLV=() LMSG=()
SESSION_START=$(date '+%F %T')
SAVED_STTY=""

# log LEVEL message...   (tab separated: time, level, message). Never pass passwords.
log() {
    local lv=$1; shift
    printf '%s\t%s\t%s\n' "$(date '+%F %T')" "$lv" "$*" >>"$LOGFILE" 2>/dev/null
}

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
# title TEXT -> TITLE (TEXT padded with spaces to the terminal width)
title() {
    local sp
    printf -v sp '%*s' $((COLUMNS - ${#1})) ''
    TITLE=$1$sp
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
    if (($? > 128)); then KEY=NONE; return; fi   # interrupted (e.g. SIGWINCH)
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

# ---------- data ----------
load_users() {
    NAMES=() UIDS=() GIDS=() HOMES=() SHELLS=()
    SUDOER=() PWF=() LASTCHG=() LASTLOG=() FLAGS=() PWST=() SHMAX=() SHEXP=() NFLAG=0
    TODAY=$(( $(date +%s) / 86400 ))
    local k v g gid mem m u p lc mx ex n h s uid line hdr off rest first=1
    while read -r k v; do
        case $k in UID_MIN) UID_MIN=$v ;; UID_MAX) UID_MAX=$v ;; esac
    done 2>/dev/null </etc/login.defs

    SUDOGID=-1
    local grp
    for grp in sudo admin; do
        IFS=: read -r g _ gid mem < <(getent group "$grp")
        [[ -z $g ]] && continue
        [[ $grp == sudo ]] && SUDOGID=$gid
        local -a arr
        IFS=, read -ra arr <<<"$mem"
        for m in "${arr[@]}"; do SUDOER[$m]=1; done
    done

    while IFS=: read -r u p lc _ mx _ _ ex _; do PWF[$u]=$p; LASTCHG[$u]=$lc; SHMAX[$u]=$mx; SHEXP[$u]=$ex; done 2>/dev/null </etc/shadow

    # passwd -S -a: "name STATUS date min max warn inactive"; STATUS is P (usable), L (locked) or NP (none)
    while read -r u p _; do PWST[$u]=$p; done < <(passwd -S -a 2>/dev/null)

    # lastlog: fixed-width columns, "Latest" column offset taken from the header.
    # Stored compact ("Oct20 22:14"); users missing from the map are shown as "never".
    while IFS= read -r line; do
        if ((first)); then
            first=0
            hdr=${line%%Latest*}; off=${#hdr}
            continue
        fi
        u=${line%% *}
        rest=${line:off}
        rest=${rest#"${rest%%[![:space:]]*}"}
        if [[ -z $rest || $rest == *Never* ]]; then continue; fi
        local -a w=($rest)
        if [[ ${w[0]} == [0-9][0-9][0-9][0-9]-* ]]; then
            LASTLOG[$u]="${w[0]:5:5} ${w[0]:11:5}"
        else
            LASTLOG[$u]="${w[1]}${w[2]} ${w[3]:0:5}"
        fi
    done < <(lastlog 2>/dev/null)

    local fl
    while IFS=: read -r n _ uid gid _ h s; do
        NAMES+=("$n") UIDS+=("$uid") GIDS+=("$gid") HOMES+=("$h") SHELLS+=("$s")
        ((gid == SUDOGID)) && SUDOER[$n]=1
        # audit flags
        fl=""
        if ((uid == 0)) && [[ $n != root ]]; then fl+="uid0 "; fi
        if [[ -n ${PWF[$n]+set} && -z ${PWF[$n]} ]]; then fl+="nopass "; fi
        if ! { ((uid >= UID_MIN && uid <= UID_MAX)) || ((uid == 0)); }; then
            case $s in */nologin|*/false|*/sync|*/halt|*/shutdown) ;; *) fl+="shell " ;; esac
        fi
        if [[ -n $fl ]]; then FLAGS[$n]=${fl% }; ((NFLAG++)); fi
    done < <(getent passwd | sort -t: -k3,3n -k1,1)
}

# human accounts and anything flagged by the audit (which includes UID-0 impostors)
in_scope() {
    local uid=${UIDS[$1]}
    ((uid >= UID_MIN && uid <= UID_MAX)) && return 0
    [[ -n ${FLAGS[${NAMES[$1]}]} ]]
}

flag_text() {  # flag_text index -> REASON
    local i=$1 f=${FLAGS[${NAMES[$1]}]} out=""
    [[ $f == *uid0* ]] && out+="UID 0 but not root (backdoor); "
    [[ $f == *nopass* ]] && out+="empty password in /etc/shadow; "
    [[ $f == *shell* ]] && out+="system account with login shell (${SHELLS[i]:-none}); "
    REASON=${out%; }
}

row_info() {  # row_info index -> R_ROLE R_ROLEC R_STATE R_STATEC
    local name=${NAMES[$1]} uid=${UIDS[$1]} pw
    R_ROLEC=""
    if ((uid == 0)) && [[ $name != root ]]; then R_ROLE="ROOT!"; R_ROLEC=$'\e[1;91m'
    elif [[ $name == root ]]; then R_ROLE="root"
    elif [[ -n ${SUDOER[$name]} ]]; then R_ROLE="admin"; R_ROLEC=$'\e[33m'
    else R_ROLE="std"
    fi
    R_STATE="" R_STATEC=$'\e[33m'
    pw=${PWF[$name]-x}
    if [[ -z $pw ]]; then R_STATE="NOPASS"; R_STATEC=$'\e[1;91m'
    elif [[ $pw == '!'* || $pw == '*'* ]]; then R_STATE="locked"
    elif [[ ${LASTCHG[$name]-} == 0 ]]; then R_STATE="chg@login"; R_STATEC=$'\e[36m'
    fi
    if [[ $name == "$SUDO_USER" ]]; then R_STATE+="${R_STATE:+ }you"; fi
}

# System-wide settings shown in the banner: login.defs aging (new accounts only) and pam_pwquality.
load_policy() {
    local k v maxd="" mind="" warn="" enc="" line f found=0 pq="" conf=""
    while read -r k v; do
        case $k in
            PASS_MAX_DAYS) maxd=$v ;; PASS_MIN_DAYS) mind=$v ;;
            PASS_WARN_AGE) warn=$v ;; ENCRYPT_METHOD) enc=$v ;;
        esac
    done 2>/dev/null </etc/login.defs
    POL_AGE="max ${maxd:-?}  min ${mind:-?}  warn ${warn:-?}  hash ${enc:-default}"
    POL_AGE_BAD=0
    if [[ -z $maxd ]] || ((maxd >= 99999)); then POL_AGE_BAD=1; fi

    for f in /etc/pam.d/*; do
        while IFS= read -r line; do
            [[ $line == [[:space:]]*'#'* || $line == '#'* ]] && continue
            if [[ $line == *pam_pwquality.so* || $line == *pam_cracklib.so* ]]; then
                found=1; pq=${line#*.so}; pq=${pq#"${pq%%[![:space:]]*}"}; break 2
            fi
        done 2>/dev/null <"$f"
    done
    while IFS= read -r line; do
        [[ -z $line || $line == [[:space:]]*'#'* || $line == '#'* ]] && continue
        conf+="${line//[[:space:]]/} "
    done 2>/dev/null </etc/security/pwquality.conf
    conf=${conf% }
    POL_PQ_BAD=0
    if ((found)); then POL_PQ="pam_pwquality ${pq:-(no args)}"
    else POL_PQ="pam_pwquality NOT enabled in /etc/pam.d"; POL_PQ_BAD=1; fi
    POL_PQ+="  |  pwquality.conf: ${conf:-defaults (nothing set)}"
    [[ -z $conf ]] && POL_PQ_BAD=1
}

# age_info user -> A_AGE (days since change), A_EXP (days until password/account expiry), A_COL
age_info() {
    local lc=${LASTCHG[$1]-} mx=${SHMAX[$1]-} ex=${SHEXP[$1]-} left
    A_COL=$'\e[90m'
    if [[ -z $lc ]]; then A_AGE="-" A_EXP="-"; return; fi
    if ((lc == 0)); then A_AGE="must" A_COL=$'\e[36m'; else A_AGE="$((TODAY - lc))d"; fi
    A_EXP="never"
    if [[ -n $mx && $mx != 99999 && $mx -ge 0 ]] 2>/dev/null; then
        if ((lc == 0)); then A_EXP="now"; A_COL=$'\e[36m'
        else
            left=$((lc + mx - TODAY))
            if ((left < 0)); then A_EXP="EXPIRED"; A_COL=$'\e[1;91m'
            else A_EXP="in ${left}d"; ((left <= 14)) && A_COL=$'\e[33m' || A_COL=""; fi
        fi
    fi
    if [[ -n $ex && $ex != -1 ]] && ((ex <= TODAY)); then A_EXP="ACCT-EXP"; A_COL=$'\e[1;91m'; fi
}

remember_pw() {  # remember_pw user password  (call after reload so PWF is current)
    PWPLAIN[$1]=$2; PWHASH[$1]=${PWF[$1]#!}
}

pw_info() {  # pw_info user -> P_LEN (="?" when the password is not known to this tool)
    local u=$1
    if [[ -n ${PWPLAIN[$u]+set} && ${PWF[$u]#!} == "${PWHASH[$u]}" ]]; then
        P_LEN=${#PWPLAIN[$u]}
    else
        P_LEN="?"
    fi
}

build_view() {
    local curname=""
    ((${#VIEW[@]})) && curname=${NAMES[${VIEW[CUR]:-0}]}
    VIEW=()
    local i
    for i in "${!NAMES[@]}"; do
        if ((!SHOWALL)); then in_scope "$i" || continue; fi
        [[ -n $FILTER && ${NAMES[i]} != *"$FILTER"* ]] && continue
        VIEW+=("$i")
    done
    # restore cursor onto same user if possible
    CUR=0
    [[ -n $curname ]] && goto_user "$curname"
    clamp
}

goto_user() {
    local j
    for j in "${!VIEW[@]}"; do
        if [[ ${NAMES[${VIEW[j]}]} == "$1" ]]; then CUR=$j; return 0; fi
    done
    return 1
}

clamp() {
    local n=${#VIEW[@]}
    ((CUR >= n)) && CUR=$((n - 1))
    ((CUR < 0)) && CUR=0
    ((CUR < TOP)) && TOP=$CUR
    ((CUR >= TOP + LH)) && TOP=$((CUR - LH + 1))
    ((TOP < 0)) && TOP=0
}

reload() { load_users; build_view; }

# ---------- drawing ----------
draw() {
    local W=$COLUMNS i row idx buf part
    LH=$((LINES - 6)); ((SHOWPOL)) && ((LH -= 2)); ((LH < 1)) && LH=1
    clamp
    local nu=${#VIEW[@]} nsudo=0
    for i in "${VIEW[@]}"; do [[ -n ${SUDOER[${NAMES[i]}]} ]] && ((nsudo++)); done

    # title bar (issue count highlighted)
    local left=" CyberPatriot User Manager" right sp iss=""
    ((NFLAG)) && iss="$ISS $NFLAG issues $SEP "
    right="${iss}$nu shown $SEP $nsudo admin $SEP ${#MARK[@]} marked "
    ((SHOWALL)) && right="[all accounts] $right"
    [[ -n $FILTER ]] && right="[/$FILTER] $right"
    printf -v sp '%*s' $((W - ${#left} - ${#right} > 0 ? W - ${#left} - ${#right} : 1)) ''
    buf=$'\e[H\e[1;97;44m'"${left}${sp}"
    if [[ -n $iss ]]; then
        local pre_r=${right%%"$iss"*}
        buf+="$pre_r"$'\e[1;93m'"$iss"$'\e[1;97m'"${right#*"$iss"}"
    else
        buf+="$right"
    fi
    buf+=$'\e[0m\e[K\n'

    # system policy banner
    if ((SHOWPOL)); then
        local pa=$'\e[36m' pq=$'\e[36m'
        ((POL_AGE_BAD)) && pa=$'\e[1;93m'; ((POL_PQ_BAD)) && pq=$'\e[1;93m'
        local l1=" Aging  (login.defs): $POL_AGE" l2=" Quality (pwquality): $POL_PQ"
        buf+="$pa${l1:0:W}"$'\e[0m\e[K\n'"$pq${l2:0:W}"$'\e[0m\e[K\n'
    fi

    # column header
    local hdr
    printf -v hdr ' %-3s%-16s %6s  %-6s %-12s %-11s ' '' USER UID ROLE STATE LAST-LOGIN
    ((SHOWPW)) && hdr+='PW  '
    ((SHOWAGE)) && hdr+='AGE   EXPIRES  '
    ((SHOWLEN)) && hdr+='LEN '
    hdr+=SHELL
    buf+=$'\e[1;36m'"${hdr:0:W}"$'\e[0m\e[K\n'

    local tailw=$((W - 61)); ((SHOWPW)) && ((tailw -= 4)); ((SHOWAGE)) && ((tailw -= 15)); ((SHOWLEN)) && ((tailw -= 4)); ((tailw < 0)) && tailw=0
    for ((row = 0; row < LH; row++)); do
        idx=$((TOP + row))
        if ((idx >= nu)); then
            if ((nu == 0 && row == 0)); then buf+=$'\e[2m  (no users match)\e[0m\e[K\n'; else buf+=$'\e[K\n'; fi
            continue
        fi
        i=${VIEW[idx]}
        local name=${NAMES[i]} uid=${UIDS[i]}
        local base=$'\e[39m' pre="" sel=0
        ((idx == CUR)) && { sel=1; pre=$'\e[48;5;24m\e[97m'; base=$'\e[97m'; }

        local mk=" " mkc=""; [[ -n ${MARK[$name]} ]] && mk=$MK mkc=$'\e[92m'
        row_info "$i"

        local last=${LASTLOG[$name]-never} last_c=""
        if [[ $last == never ]]; then ((sel)) && last_c=$'\e[37m' || last_c=$'\e[90m'; fi

        local sh=${SHELLS[i]##*/} sh_c=""
        [[ -z ${SHELLS[i]} ]] && sh="(none)"
        [[ ${FLAGS[$name]} == *shell* ]] && sh_c=$'\e[91m'

        local line="$pre$base $mkc$mk  $base"
        printf -v part '%-16.16s %6s  ' "$name" "$uid"
        line+="$part"
        printf -v part '%-6s ' "$R_ROLE"; line+="$R_ROLEC$part$base"
        printf -v part '%-12.12s ' "$R_STATE"; line+="$R_STATEC$part$base"
        printf -v part '%-11s ' "$last"; line+="$last_c$part$base"
        if ((SHOWPW)); then
            local ps=${PWST[$name]:-?} psc=$'\e[90m'
            case $ps in P) psc=$'\e[92m' ;; L) psc=$'\e[33m' ;; NP) psc=$'\e[1;91m' ;; esac
            printf -v part '%-3s ' "$ps"; line+="$psc$part$base"
        fi
        if ((SHOWAGE)); then
            age_info "$name"
            local ac=$A_COL; ((sel)) && [[ $ac == $'\e[90m' ]] && ac=$'\e[37m'
            printf -v part '%-5s %-8s ' "$A_AGE" "$A_EXP"; line+="$ac$part$base"
        fi
        if ((SHOWLEN)); then
            pw_info "$name"
            local pc=$'\e[90m'; ((sel)) && pc=$'\e[37m'
            [[ $P_LEN != '?' ]] && { if ((P_LEN < PWMIN)); then pc=$'\e[1;91m'; else pc=$'\e[92m'; fi; }
            printf -v part '%-3s ' "$P_LEN"; line+="$pc$part$base"
        fi
        printf -v part '%-*.*s' "$tailw" "$tailw" "$sh"; line+="$sh_c$part"
        buf+="$line"$'\e[0m\e[K\n'
    done

    # rule + scroll hints
    local info=""
    ((TOP > 0)) && info+=" $UP_ARR more "
    ((TOP + LH < nu)) && info+=" $DN_ARR more "
    local rule; printf -v rule '%*s' $((W - ${#info})) ''
    buf+=$'\e[2m'"${rule// /$HR}${info}"$'\e[0m\e[K\n'

    # status line
    buf+=$'\e['"$SC"'m '"${ST:0:W-2}"$'\e[0m\e[K\n'

    # key hints (wrap onto two lines)
    local -a hints=("$KUD:move" "Spc:mark" "n:new" "d:del" "s:sudo" "p:pass" "l:lock" "f:force-chg"
                    "c:chage" "w:pw-status" "C:age" "W:pw-len" "P:policy" "e:export" "i:issues" "?:help" "q:quit" "x:nologin" "/:find" "t:system")
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
        "  Space              mark / unmark       a  mark all      A  clear marks"
        "  n                  new user (name, password, sudo?, force change?)"
        "  d  Del             delete user(s)      (asks about home dir)"
        "  s                  toggle sudo group   (sudo + admin)"
        "  p                  change password     (same pw for all marked)"
        "  f                  force password change at next login"
        "  l                  lock / unlock account"
        "  w                  show/hide PW column (passwd -S: P set, L locked, NP none)"
        "  c                  chage -l for the highlighted user (age / expiry detail)"
        "  C                  show/hide AGE + EXPIRES columns (from /etc/shadow)"
        "  P                  show/hide the system password policy banner"
        "                     (login.defs aging only affects NEW accounts; use chage for existing)"
        "  W                  show/hide LEN column (only for passwords set via this tool"
        "                     this session, else ?; < $PWMIN is red; never logged/exported)"
        "  x                  set shell to nologin (fix system accts with login shell)"
        "  i                  issues view         Enter jumps to that user"
        "  e                  export Markdown report (this session's changes)"
        "  E                  export Markdown report (entire log history)"
        "  /                  filter by name      Esc clears filter"
        "  t                  toggle system accounts"
        "  r                  reload              q  quit"
        ""
        "Actions apply to marked users, or the highlighted user if none marked."
        "Red = UID 0 backdoor / empty password / system account with login shell."
        "Shown by default: UID >= $UID_MIN, UID 0 impostors, and anything flagged."
        "Log:    $LOGFILE"
        "Report: Desktop of \$SUDO_USER (else their home, else /root)"
        ""
        "  press any key"
    )
    title " Help"
    local buf=$'\e[H\e[J\e[1;97;44m'"$TITLE"$'\e[0m\n\n'
    local l; for l in "${lines[@]}"; do buf+="$l"$'\n'; done
    printf '%s' "$buf"
    readkey
}

show_chage() {
    ((${#VIEW[@]})) || return
    local u=${NAMES[${VIEW[CUR]}]} out
    out=$(chage -l "$u" 2>&1)
    title " chage -l $u"
    printf '\e[H\e[J\e[1;97;44m%s\e[0m\n\n%s\n\n\e[2m  press any key\e[0m\n' "$TITLE" "$out"
    readkey
}

# Issues view: JUMP is set to a user name when Enter is pressed.
show_issues() {
    JUMP=""
    local -a IL=()
    local i
    for i in "${!NAMES[@]}"; do [[ -n ${FLAGS[${NAMES[i]}]} ]] && IL+=("$i"); done
    local c=0 t=0 n=${#IL[@]} lh r idx buf rule line
    while :; do
        get_size
        lh=$((LINES - 4)); ((lh < 1)) && lh=1
        ((c >= n)) && c=$((n - 1)); ((c < 0)) && c=0
        ((c < t)) && t=$c; ((c >= t + lh)) && t=$((c - lh + 1))
        title " Security issues ($n)"
        buf=$'\e[H\e[1;97;41m'"$TITLE"$'\e[0m\e[K\n'
        printf -v line ' %-16s %6s  %s' USER UID PROBLEM
        buf+=$'\e[1;36m'"$line"$'\e[0m\e[K\n'
        for ((r = 0; r < lh; r++)); do
            idx=$((t + r))
            if ((idx >= n)); then
                if ((n == 0 && r == 0)); then buf+=$'\e[32m  No issues found.\e[0m\e[K\n'; else buf+=$'\e[K\n'; fi
                continue
            fi
            i=${IL[idx]}; flag_text "$i"
            printf -v line ' %-16.16s %6s  %s' "${NAMES[i]}" "${UIDS[i]}" "$REASON"
            line=${line:0:COLUMNS}
            if ((idx == c)); then buf+=$'\e[48;5;24m\e[97m'"$line"$'\e[0m\e[K\n'
            else buf+=$'\e[91m'"$line"$'\e[0m\e[K\n'; fi
        done
        printf -v rule '%*s' "$COLUMNS" ''
        buf+=$'\e[2m'"${rule// /$HR}"$'\e[0m\e[K\n'
        buf+=$'\e[1;36m '"$KUD"$'\e[0m\e[90m move  \e[0m\e[1;36mEnter\e[0m\e[90m jump to user  \e[0m\e[1;36mEsc\e[0m\e[90m back\e[0m\e[K\e[J'
        printf '%s' "$buf"
        readkey
        case $KEY in
            UP|k)   ((c--)) ;;
            DOWN|j) ((c++)) ;;
            PGUP)   c=$((c - lh)) ;;
            PGDN)   c=$((c + lh)) ;;
            HOME|g) c=0 ;;
            END|G)  c=$((n - 1)) ;;
            ENTER)  ((n)) && JUMP=${NAMES[${IL[c]}]}; return ;;
            ESC|q|Q) return ;;
        esac
    done
}

# ---------- prompts ----------
prompt() {   # prompt "label" [secret]  -> PVAL ; returns 1 on Esc
    local label=$1 secret=${2:-0} s="" disp
    printf '\e[?25h'
    while :; do
        disp=$s; ((secret)) && disp=${s//?/*}
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
    return 0
}

confirm() {  # confirm "question" [default y|n]
    local def=${2:-n} hint='[y/N]'
    [[ $def == y ]] && hint='[Y/n]'
    printf '\e[%d;1H\e[K\e[1;33m %s %s\e[0m' "$LINES" "$1" "$hint"
    while :; do
        readkey
        case $KEY in
            y|Y) return 0 ;;
            n|N|ESC) return 1 ;;
            ENTER) [[ $def == y ]]; return ;;
        esac
    done
}

typed_confirm() {  # require typing the username
    prompt "Type '$1' to confirm:" 0 || return 1
    [[ $PVAL == "$1" ]]
}

ask_password() {  # sets PVAL ; returns 1 on cancel/mismatch
    local p1 p2
    prompt "New password:" 1 || return 1
    p1=$PVAL
    if [[ -z $p1 ]]; then ST="Empty password refused"; SC=31; return 1; fi
    prompt "Confirm password:" 1 || return 1
    p2=$PVAL
    if [[ $p1 != "$p2" ]]; then ST="Passwords do not match"; SC=31; return 1; fi
    if ((${#p1} < 8)); then
        confirm "Password is shorter than 8 chars. Use anyway?" n || { cancel; return 1; }
    fi
    PVAL=$p1
}

# ---------- actions ----------
cancel() { ST="Cancelled"; SC=33; }

run() {  # run "description" cmd args...
    local d=$1 o rc; shift
    o=$("$@" 2>&1); rc=$?
    if ((rc == 0)); then log OK "$d"; LASTERR=""; return 0; fi
    LASTERR=${o//$'\n'/ }
    log FAIL "($rc) $d: $LASTERR"
    return $rc
}

chpw() { printf '%s:%s\n' "$1" "$2" | chpasswd 2>/dev/null; }

# Make the operator type their own name before touching their own account.
guard_self() {
    [[ $1 == "$SUDO_USER" ]] || return 0
    typed_confirm "$1" || { ST="Skipped $1"; SC=33; return 1; }
}

# Remove root from TG (optional $1: status message); fails if nothing is left.
drop_root() {
    local keep=() u
    for u in "${TG[@]}"; do
        if [[ $u != root ]]; then keep+=("$u"); elif [[ -n $1 ]]; then ST=$1; SC=31; fi
    done
    TG=("${keep[@]}")
    ((${#TG[@]}))
}

targets() {  # fills TG with marked (visible) users, else the cursor user
    TG=()
    local i
    for i in "${VIEW[@]}"; do [[ -n ${MARK[${NAMES[i]}]} ]] && TG+=("${NAMES[i]}"); done
    if ((${#TG[@]} == 0 && ${#VIEW[@]} > 0)); then TG=("${NAMES[${VIEW[CUR]}]}"); fi
}

summary() {  # summary "verb" ok fail
    if (($3 == 0)); then ST="$1: $2 user(s)"; SC=32
    else ST="$1: $2 ok, $3 failed - $LASTERR"; SC=31; fi
}

act_new() {
    local u pw sud=0 force=0
    prompt "New username:" 0 || { cancel; return; }
    u=$PVAL
    if [[ ! $u =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then ST="Invalid username '$u'"; SC=31; return; fi
    if getent passwd "$u" >/dev/null; then ST="User '$u' already exists"; SC=31; return; fi
    ask_password || { [[ $SC == 31 ]] || cancel; return; }
    pw=$PVAL
    confirm "Give '$u' sudo?" n && sud=1
    confirm "Force password change at first login?" n && force=1
    if ! run "useradd -m $u" useradd -m -s /bin/bash "$u"; then ST="useradd failed: $LASTERR"; SC=31; return; fi
    if ! chpw "$u" "$pw"; then
        log FAIL "set password for new user $u"
        ST="Created $u but setting password failed"; SC=31; reload; return
    fi
    log OK "set password for new user $u"
    ((sud)) && run "gpasswd -a $u sudo" gpasswd -a "$u" sudo
    ((force)) && run "passwd -e $u (force change at next login)" passwd -e "$u"
    reload
    remember_pw "$u" "$pw"
    goto_user "$u"
    ST="Created $u"; ((sud)) && ST+=" (sudo)"; ((force)) && ST+=" (must change pw)"; SC=32
}

act_delete() {
    targets; ((${#TG[@]})) || return
    local u list flag="" ok=0 fail=0
    drop_root "Refusing to touch root" || return
    list="${TG[*]}"
    confirm "DELETE ${#TG[@]} user(s): ${list:0:60}?" n || { cancel; return; }
    confirm "Also remove home directories / mail?" y && flag="-r"
    for u in "${TG[@]}"; do
        guard_self "$u" || continue
        run "userdel $flag $u" userdel $flag "$u"
        if getent passwd "$u" >/dev/null && [[ $LASTERR == *"used by process"* ]] \
            && confirm "$u has running processes. Kill them and force delete?" n; then
            pkill -KILL -u "$u" 2>/dev/null
            run "userdel -f $flag $u" userdel -f $flag "$u"
        fi
        if getent passwd "$u" >/dev/null; then ((fail++)); else ((ok++)); unset 'MARK[$u]' 'PWPLAIN[$u]' 'PWHASH[$u]'; fi
    done
    reload; summary "Deleted" "$ok" "$fail"
}

act_sudo() {
    targets; ((${#TG[@]})) || return
    local u g f groups ok=0 fail=0 added=0 removed=0
    for u in "${TG[@]}"; do
        [[ $u == root ]] && continue
        if [[ -n ${SUDOER[$u]} ]]; then
            guard_self "$u" || continue
            f=0 groups=" $(id -nG "$u" 2>/dev/null) "
            for g in sudo admin; do
                [[ $groups == *" $g "* ]] && { run "gpasswd -d $u $g" gpasswd -d "$u" "$g" || f=1; }
            done
            ((f)) && ((++fail)) || ((++ok, ++removed))
        else
            run "gpasswd -a $u sudo" gpasswd -a "$u" sudo && ((++ok, ++added)) || ((++fail))
        fi
    done
    reload
    if ((fail)); then summary "sudo toggle" "$ok" "$fail"
    else ST="sudo: +$added added, -$removed removed"; SC=32; fi
}

act_passwd() {
    targets; ((${#TG[@]})) || return
    ask_password || { [[ $SC == 31 ]] || cancel; return; }
    local pw=$PVAL u ok=0 fail=0 done_=()
    for u in "${TG[@]}"; do
        if chpw "$u" "$pw"; then log OK "passwd $u"; ((ok++)); done_+=("$u")
        else log FAIL "passwd $u"; LASTERR="chpasswd failed for $u"; ((fail++)); fi
    done
    reload
    for u in "${done_[@]}"; do remember_pw "$u" "$pw"; done
    summary "Password changed" "$ok" "$fail"
}

act_force() {
    targets; ((${#TG[@]})) || return
    local u ok=0 fail=0
    for u in "${TG[@]}"; do
        [[ $u == root ]] && continue
        run "passwd -e $u (force change at next login)" passwd -e "$u" && ((++ok)) || ((++fail))
    done
    reload; summary "Must change password at next login" "$ok" "$fail"
}

act_lock() {
    targets; ((${#TG[@]})) || return
    local u ok=0 fail=0 pw
    for u in "${TG[@]}"; do
        [[ $u == root ]] && continue
        pw=${PWF[$u]-}
        if [[ $pw == '!' || $pw == '!!' || $pw == '!*' || $pw == '*'* ]]; then
            LASTERR="$u has no usable password hash (set one with p)"; ((fail++))
        elif [[ $pw == '!'* ]]; then
            run "usermod -U $u" usermod -U "$u" && ((++ok)) || ((++fail))
        else
            guard_self "$u" || continue
            run "usermod -L $u" usermod -L "$u" && ((++ok)) || ((++fail))
        fi
    done
    reload; summary "Lock toggled" "$ok" "$fail"
}

act_shell() {
    targets; ((${#TG[@]})) || return
    local u ok=0 fail=0 list
    drop_root || return
    list="${TG[*]}"
    confirm "Set shell to /usr/sbin/nologin for: ${list:0:50}?" n || { cancel; return; }
    for u in "${TG[@]}"; do
        run "usermod -s /usr/sbin/nologin $u" usermod -s /usr/sbin/nologin "$u" && ((++ok)) || ((++fail))
    done
    reload; summary "Shell set to nologin" "$ok" "$fail"
}

# ---------- markdown report ----------
collect_log() {  # collect_log session|full -> LTS LLV LMSG (OK/FAIL entries only)
    LTS=() LLV=() LMSG=()
    local ts lv msg
    [[ -r $LOGFILE ]] || return
    while IFS=$'\t' read -r ts lv msg; do
        if [[ $lv == START && $1 == session ]]; then LTS=() LLV=() LMSG=(); fi
        case $lv in OK|FAIL) LTS+=("$ts") LLV+=("$lv") LMSG+=("$msg") ;; esac
    done <"$LOGFILE"
}

act_export() {  # act_export session|full
    local mode=$1 home="" dir f stamp i n g mem osname
    if [[ -n $SUDO_USER && $SUDO_USER != root ]]; then
        IFS=: read -r _ _ _ _ _ home _ < <(getent passwd "$SUDO_USER")
    fi
    [[ -z $home || ! -d $home ]] && home=/root
    dir=$home; [[ -d $home/Desktop ]] && dir=$home/Desktop
    stamp=$(date '+%Y%m%d-%H%M%S')
    f=$dir/usermgr-report-$stamp.md
    osname=$( . /etc/os-release 2>/dev/null; printf '%s' "${PRETTY_NAME:-unknown}" )
    collect_log "$mode"

    {
        printf '# CyberPatriot User Report\n\n'
        printf -- '- **Host:** %s\n- **OS:** %s\n- **Generated:** %s\n- **Operator:** %s\n' \
            "${HOSTNAME:-?}" "$osname" "$(date '+%F %T')" "${SUDO_USER:-root}"
        if [[ $mode == session ]]; then printf -- '- **Scope:** this session (started %s)\n\n' "$SESSION_START"
        else printf -- '- **Scope:** full log history (%s)\n\n' "$LOGFILE"; fi

        printf '## Changes\n\n'
        if ((${#LMSG[@]} == 0)); then
            printf '_No changes recorded._\n\n'
        else
            printf '| Time | Result | Action |\n|---|---|---|\n'
            for i in "${!LMSG[@]}"; do
                printf '| %s | %s | `%s` |\n' "${LTS[i]}" "${LLV[i]}" "${LMSG[i]//|/\\|}"
            done
            printf '\n'
        fi

        printf '## Security findings (current)\n\n'
        if ((NFLAG == 0)); then
            printf '_None._\n\n'
        else
            printf '| User | UID | Issue |\n|---|---|---|\n'
            for i in "${!NAMES[@]}"; do
                [[ -n ${FLAGS[${NAMES[i]}]} ]] || continue
                flag_text "$i"
                printf '| %s | %s | %s |\n' "${NAMES[i]}" "${UIDS[i]}" "$REASON"
            done
            printf '\n'
        fi

        printf '## Users (current)\n\n| User | UID | Role | State | PW (passwd -S) | Last login | Shell |\n|---|---|---|---|---|---|---|\n'
        for i in "${!NAMES[@]}"; do
            in_scope "$i" || continue
            row_info "$i"
            printf '| %s | %s | %s | %s | %s | %s | %s |\n' "${NAMES[i]}" "${UIDS[i]}" "$R_ROLE" \
                "${R_STATE:--}" "${PWST[${NAMES[i]}]:-?}" "${LASTLOG[${NAMES[i]}]-never}" "${SHELLS[i]:-none}"
        done

        printf '\n## System password policy\n\n'
        printf -- '- **Aging (login.defs, new accounts):** %s\n- **Complexity:** %s\n' "$POL_AGE" "$POL_PQ"

        printf '\n## Admin groups\n\n'
        for n in sudo admin; do
            IFS=: read -r g _ _ mem < <(getent group "$n")
            [[ -n $g ]] && printf -- '- **%s:** %s\n' "$n" "${mem:-_(none)_}"
        done
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
    local n k
    while :; do
        get_size
        n=${#VIEW[@]}
        draw
        readkey
        ST=""; SC=32
        case $KEY in
            UP|k)   ((CUR--)) ;;
            DOWN|j) ((CUR++)) ;;
            PGUP)   CUR=$((CUR - LH + 1)) ;;
            PGDN)   CUR=$((CUR + LH - 1)) ;;
            HOME|g) CUR=0 ;;
            END|G)  CUR=$((n - 1)) ;;
            ' ')    if ((n)); then
                        k=${NAMES[${VIEW[CUR]}]}
                        if [[ -n ${MARK[$k]} ]]; then unset 'MARK[$k]'; else MARK[$k]=1; fi
                        ((CUR++))
                    fi ;;
            a)      for k in "${VIEW[@]}"; do MARK[${NAMES[k]}]=1; done ;;
            A)      MARK=() ;;
            n)      act_new ;;
            d|DEL)  act_delete ;;
            s)      act_sudo ;;
            p)      act_passwd ;;
            f)      act_force ;;
            l)      act_lock ;;
            c)      show_chage ;;
            C)      ((SHOWAGE ^= 1)) ;;
            P)      ((SHOWPOL ^= 1)) ;;
            w)      ((SHOWPW ^= 1))
                    ST="PW status column ${ONOFF[SHOWPW]} (passwd -S: P set, L locked, NP none)"; SC=36 ;;
            W)      ((SHOWLEN ^= 1))
                    ST="Length column ${ONOFF[SHOWLEN]} (red = under $PWMIN)"; SC=36 ;;
            x)      act_shell ;;
            e)      act_export session ;;
            E)      act_export full ;;
            i)      show_issues
                    if [[ -n $JUMP ]]; then
                        goto_user "$JUMP" || { FILTER=""; SHOWALL=0; build_view; goto_user "$JUMP"; }
                    fi ;;
            '/')    if prompt "Filter:" 0; then FILTER=$PVAL; build_view; fi ;;
            t)      ((SHOWALL ^= 1)); build_view
                    ST=${SCOPE_MSG[SHOWALL]}; SC=36 ;;
            r)      reload; ST="Reloaded"; SC=36 ;;
            '?'|h)  show_help ;;
            ESC)    if [[ -n $FILTER ]]; then FILTER=""; build_view; fi ;;
            q|Q)    return ;;
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
load_policy
reload
log START "session start (invoked by ${SUDO_USER:-root})"
for i in "${!NAMES[@]}"; do
    if [[ -n ${FLAGS[${NAMES[i]}]} ]]; then flag_text "$i"; log FIND "${NAMES[i]}: $REASON"; fi
done
main_loop
