#!/usr/bin/env bash
# pkgaudit.sh - keyboard-driven unauthorized-software finder for CyberPatriot (Linux Mint 21)
# Pure bash + dpkg/apt (snap/flatpak optional). Run with: sudo ./pkgaudit.sh [--baseline FILE] [--keep FILE]
# Press ? inside for keybinds. R writes a Markdown post-round report.

LOGFILE=/var/log/pkgaudit.log
KEEPFILE=/root/pkgaudit.keep
BASEFILE=""
QROOT=/root/pkgaudit-quarantine
QDIR=$QROOT/$(date +%Y%m%d-%H%M%S)

while (($#)); do
    case $1 in
        --baseline) [[ -n $2 ]] || { echo "pkgaudit: --baseline needs a file" >&2; exit 1; }; BASEFILE=$2; shift 2 ;;
        --keep)     [[ -n $2 ]] || { echo "pkgaudit: --keep needs a file" >&2; exit 1; }; KEEPFILE=$2; shift 2 ;;
        -h|--help)  echo "usage: sudo $0 [--baseline FILE] [--keep FILE]"; exit 0 ;;
        *)          echo "pkgaudit: unknown option $1" >&2; exit 1 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "pkgaudit: must be run as root (try: sudo $0)" >&2
    exit 1
fi
if [[ ! -t 0 || ! -t 1 ]]; then
    echo "pkgaudit: needs an interactive terminal" >&2
    exit 1
fi
for c in dpkg dpkg-query apt-get apt-cache apt-mark zcat find sort stat less stty readlink xargs grep mktemp; do
    command -v "$c" >/dev/null || { echo "pkgaudit: missing command: $c" >&2; exit 1; }
done

# ---------- glyphs ----------
if [[ ${LC_ALL:-${LC_CTYPE:-$LANG}} == *[Uu][Tt][Ff]* ]]; then
    HR='─' MK='●' KUD='↑↓' UP_ARR='↑' DN_ARR='↓' SEP='·' ELL='…'
else
    HR='-' MK='*' KUD='Up/Dn' UP_ARR='^' DN_ARR='v' SEP='|' ELL='~'
fi

# ---------- state ----------
CATS=(HACK SERVER GAME P2P NEW XPKG FILE)
declare -A CATN=([HACK]=1 [SERVER]=2 [GAME]=3 [P2P]=4 [NEW]=5 [XPKG]=6 [FILE]=7)
declare -A CATC=([HACK]='1;91' [SERVER]='93' [GAME]='32' [P2P]='35' [NEW]='36' [XPKG]='34' [FILE]='33')
declare -A CNT=() MARK=() KEEP=() BASE=() MAN=() HIST=() PROTX=() OWN=() CAN=() FSEEN=()
NM=() CT=() SRC=() VER=() DT=() EX=() WH=() STT=() QP=()          # one entry per finding
A_TM=() A_ACT=() A_TG=() A_VER=() A_XT=() A_RC=() A_CT=()         # actions taken (for report)
VIEW=() PLAN=() GONE=() TG=() FP=() FK=()
CUR=0 TOP=0 LH=10 REPN=0
FILTER="" CATF=""
ST="" SC=32
KEY="" PVAL="" CH="" LT="" MD="" D="" WARN="" PFILE="" RC=0 LASTERR=""
BASEMODE="" BASEDESC="" BASECNT=0
SAVED_STTY=""

NAME_RE='^[a-z0-9][a-z0-9+.-]*(:[a-z0-9]+)?$'
SNAP_RE='^[a-z0-9][a-z0-9-]*$'
FLAT_RE='^[A-Za-z0-9][A-Za-z0-9._-]*$'

declare -A L_HACK=() L_SERVER=() L_P2P=() L_GAME=()
mklist() { local -n _a=$1; shift; local n; for n in "$@"; do _a[$n]=1; done; }
# Exact package names only. Looked up in an associative array, never used as a glob.
mklist L_HACK nmap zenmap wireshark wireshark-qt wireshark-gtk wireshark-common tshark john john-data hydra hydra-gtk \
    ophcrack ophcrack-cli aircrack-ng hashcat nikto sqlmap netcat netcat-traditional ncat ettercap-common ettercap-graphical \
    ettercap-text-only dsniff medusa fcrackzip pdfcrack kismet yersinia crunch netdiscover masscan wifite reaver macchanger \
    dnsrecon rainbowcrack sucrack cewl hping3 nbtscan snort metasploit-framework burpsuite
mklist L_SERVER vsftpd proftpd-basic proftpd-core pure-ftpd telnetd inetutils-telnetd openbsd-inetd xinetd rsh-server \
    tftpd-hpa atftpd apache2 nginx lighttpd samba nfs-kernel-server bind9 postfix dovecot-core dovecot-imapd dovecot-pop3d \
    mysql-server mariadb-server snmpd x11vnc tightvncserver openssh-server
mklist L_P2P deluge deluge-gtk qbittorrent qbittorrent-nox transmission-gtk transmission-qt transmission-cli \
    transmission-common frostwire amule ktorrent tor vuze
mklist L_GAME aisleriot gnome-mines gnome-sudoku gnome-mahjongg gnome-chess quadrapassel supertux supertuxkart \
    frozen-bubble neverball extremetuxracer freeciv wesnoth minetest 0ad openarena xonotic steam steam-installer lutris kpat pysolfc

prot_pat() {
    case $1 in
        sudo|apt|apt-utils|dpkg|bash|coreutils|login|passwd|libc6|systemd*|dbus*|grub-*|mint-*|linux-*|ubuntu-*|cinnamon*|mate-desktop*|lightdm*|xorg*|network-manager*) return 0 ;;
    esac
    return 1
}
is_prot() { [[ -n ${PROTX[$1]} ]] || prot_pat "$1"; }
# Often listed as required by the README (a removed Chromium costs points): extra warning + typed PURGE.
is_soft() {
    case $1 in firefox|chromium|chromium-browser|google-chrome-stable|thunderbird|libreoffice-core) return 0 ;; esac
    return 1
}
iskept() { [[ -n ${KEEP[${NM[$1]}]} ]]; }

# log LEVEL message...   (tab separated: time, level, message)
log() {
    local lv=$1; shift
    local m=${*//[[:cntrl:]]/?}
    printf '%s\t%s\t%s\n' "$(date '+%F %T')" "$lv" "$m" >>"$LOGFILE" 2>/dev/null
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
get_size() {
    local r c
    read -r r c < <(stty size 2>/dev/null)
    LINES=${r:-24} COLUMNS=${c:-80}
    ((LINES < 10)) && LINES=10
    ((COLUMNS < 60)) && COLUMNS=60
}
pager() { restore_term; less -R "$@"; init_term; }
say() { printf '\e[%d;1H\e[K\e[1;36m %s\e[0m' "$LINES" "$1" >&2; }

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

# ---------- helpers ----------
ltrunc() {  # ltrunc str width -> LT  (sanitised, keeps the tail)
    LT=${1//[[:cntrl:]]/?}
    ((${#LT} > $2)) && LT="$ELL${LT: -$(($2 - 1))}"
}
md() {  # md str -> MD  (safe inside a markdown table cell)
    local bt='`'
    MD=${1//|/\\|}; MD=${MD//"$bt"/\'}; MD=${MD//[[:cntrl:]]/?}
}
pkgdate() {  # pkgdate name -> D  (install date from the dpkg file list mtime)
    local f e=""
    for f in "/var/lib/dpkg/info/$1.list" "/var/lib/dpkg/info/$1:amd64.list"; do
        [[ -e $f ]] && { e=$(stat -c %Y -- "$f" 2>/dev/null); break; }
    done
    if [[ -n $e ]]; then printf -v D '%(%F)T' "$e"; else D=-; fi
}
run_visible() {  # run a command outside the TUI so its output can be watched
    restore_term
    printf '\n\e[1;36m$ %s\e[0m\n\n' "$*"
    "$@"; RC=$?
    printf '\n\e[1;36m[exit %d] press any key\e[0m' "$RC"
    IFS= read -rsn1 _
    init_term
}

# ---------- data ----------
recount() {
    CNT=(); local c i
    for c in "${CATS[@]}"; do CNT[$c]=0; done
    for i in "${!NM[@]}"; do [[ -z ${STT[i]} ]] && ! iskept "$i" && ((CNT[${CT[i]}]++)); done
}

clamp() {
    local n=${#VIEW[@]}
    ((CUR >= n)) && CUR=$((n - 1))
    ((CUR < 0)) && CUR=0
    ((CUR < TOP)) && TOP=$CUR
    ((CUR >= TOP + LH)) && TOP=$((CUR - LH + 1))
    ((TOP < 0)) && TOP=0
}

build_view() {
    local cur=-1 i j f=${FILTER,,}
    ((${#VIEW[@]})) && cur=${VIEW[CUR]}
    VIEW=()
    for i in "${!NM[@]}"; do
        [[ -n $CATF && ${CT[i]} != "$CATF" ]] && continue
        if [[ -n $f ]]; then
            local hay=${NM[i],,}" "${WH[i],,}
            [[ $hay != *"$f"* ]] && continue
        fi
        VIEW+=("$i")
    done
    CUR=0
    for j in "${!VIEW[@]}"; do [[ ${VIEW[j]} == "$cur" ]] && { CUR=$j; break; }; done
    recount; clamp
}

# ---------- baseline / keep list ----------
load_keep() {
    KEEP=()
    [[ -r $KEEPFILE ]] || return
    local l
    while IFS= read -r l; do
        [[ -z $l || $l == \#* ]] || KEEP[$l]=1
    done <"$KEEPFILE"
}
save_keep() {
    if ((${#KEEP[@]})); then printf '%s\n' "${!KEEP[@]}" | sort >"$KEEPFILE"; else : >"$KEEPFILE"; fi
    chmod 600 "$KEEPFILE" 2>/dev/null
}

load_baseline() {
    BASE=() MAN=() HIST=() PROTX=() BASEMODE="" BASEDESC="" BASECNT=0
    local n k l
    say "Loading baseline..."
    if [[ -n $BASEFILE ]]; then
        if [[ -r $BASEFILE ]]; then
            while read -r n _; do [[ -n $n && $n != \#* ]] && BASE[${n%%:*}]=1; done <"$BASEFILE"
            BASEMODE=file BASEDESC="file $BASEFILE"
        else
            ST="Cannot read baseline $BASEFILE - falling back"; SC=31
        fi
    fi
    if [[ -z $BASEMODE && -r /var/log/installer/initial-status.gz ]]; then
        while read -r k n; do [[ $k == Package: ]] && BASE[$n]=1; done < <(zcat /var/log/installer/initial-status.gz 2>/dev/null)
        ((${#BASE[@]})) && BASEMODE=initial BASEDESC="installer initial-status"
    fi
    if [[ -n $BASEMODE ]]; then
        BASECNT=${#BASE[@]}
        while read -r n; do MAN[$n]=1; done < <(apt-mark showmanual 2>/dev/null)
    else
        while read -r n; do [[ -n $n ]] && HIST[$n]=1; done < <(
            zcat -f /var/log/apt/history.log* 2>/dev/null | grep '^Install:' \
                | sed 's/^Install: //; s/), /)\n/g' | grep -v automatic | sed 's/[: ].*//')
        BASEMODE=hist BASEDESC="apt history only (no clean baseline)" BASECNT=${#HIST[@]}
    fi
}

newpkg() {
    local n=$1
    is_prot "$n" && return 1
    if [[ $BASEMODE == hist ]]; then [[ -n ${HIST[$n]} ]]
    else [[ -z ${BASE[$n]} && -n ${MAN[$n]} ]]; fi
}

# ---------- scanning ----------
emit() {  # emit cat src ver date extra reason name
    local r=${6//[[:cntrl:]]/ }; r=${r//|/\/}
    printf '%s|%s|%s|%s|%s|%s|%s|%s\0' "${CATN[$1]}" "$1" "$2" "${3:--}" "${4:--}" "${5:--}" "$r" "$7"
}

scan_pkgs() {
    local n v sec pri ess st cat why
    local -A seen=()
    say "Reading installed packages..."
    while IFS='|' read -r n v sec pri ess st; do
        [[ ${st:0:2} == ii ]] || continue
        [[ -n ${seen[$n]} ]] && continue; seen[$n]=1
        if [[ $ess == yes || $pri == required || $pri == important ]]; then PROTX[$n]=1; fi
        cat="" why=""
        if [[ -n ${L_HACK[$n]} ]]; then cat=HACK why="hacking / recon tool"
        elif [[ -n ${BASE[$n]} ]]; then continue
        elif [[ -n ${L_SERVER[$n]} ]]; then cat=SERVER why="network service - check README, may be required"
        elif [[ -n ${L_P2P[$n]} ]]; then cat=P2P why="file-sharing / remote-access client"
        elif [[ -n ${L_GAME[$n]} || $sec == games || $sec == */games ]]; then cat=GAME why="game"
        elif newpkg "$n"; then
            cat=NEW
            if [[ $BASEMODE == hist ]]; then why="installed by a user per apt history.log"
            else why="manually installed, not in clean baseline"; fi
        else continue
        fi
        pkgdate "$n"
        emit "$cat" apt "$v" "$D" - "$why" "$n"
    done < <(dpkg-query -W -f='${Package}|${Version}|${Section}|${Priority}|${Essential}|${db:Status-Abbrev}\n' 2>/dev/null)
}

scan_xpkg() {
    local n v rev tr pub notes u uid h id
    if command -v snap >/dev/null; then
        say "Reading snaps..."
        while read -r n v rev tr pub notes; do
            [[ $n == Name || -z $n ]] && continue
            [[ $notes == *base* || $notes == *snapd* ]] && continue
            case $n in core|core[0-9]*|bare|snapd|gtk-common-themes|gnome-*|mesa-*) continue ;; esac
            emit XPKG snap "$v" - - "snap app" "$n"
        done < <(snap list 2>/dev/null)
    fi
    if command -v flatpak >/dev/null; then
        say "Reading flatpaks..."
        while read -r id; do
            [[ -n $id ]] && emit XPKG flatpak - - system "flatpak app (system)" "$id"
        done < <(flatpak list --app --columns=application 2>/dev/null)
        if command -v runuser >/dev/null; then
            while IFS=: read -r u _ uid _ _ h _; do
                ((uid >= 1000 && uid < 65534)) && [[ -d $h ]] || continue
                while read -r id; do
                    [[ -n $id ]] && emit XPKG flatpak - - "$u" "flatpak app (user $u)" "$id"
                done < <(runuser -u "$u" -- env HOME="$h" flatpak --user list --app --columns=application 2>/dev/null)
            done < <(getent passwd)
        fi
    fi
}

fadd() {  # fadd kind path
    [[ $2 == *[[:cntrl:]]* ]] && { log WARN "skipped path with control characters"; return; }
    [[ -n ${FSEEN[$2]} ]] && return
    FSEEN[$2]=1; FK+=("$1"); FP+=("$2")
}
desk_exec() {  # desk_exec file -> DEXF (Exec line) DEX (resolved first token)
    local l tok
    DEXF="" DEX=""
    while IFS= read -r l; do [[ $l == Exec=* ]] && { DEXF=${l#Exec=}; break; }; done <"$1" 2>/dev/null
    read -r tok _ <<<"$DEXF"; tok=${tok//\"/}
    case $tok in
        /*) DEX=$tok ;;
        ?*) DEX=$(command -v -- "$tok" 2>/dev/null) ;;
    esac
}
own_lookup() {  # own_lookup paths... -> OWN[canonical path]=owning packages (one dpkg -S pass)
    local p c line
    local -a Q=()
    for p in "$@"; do
        c=$(readlink -f -- "$p" 2>/dev/null) || continue
        [[ -z $c || $c == *'*'* || $c == *'?'* || $c == *'['* || $c == *'\'* ]] && continue   # dpkg -S treats these as patterns
        CAN[$p]=$c; Q+=("$c")
    done
    ((${#Q[@]})) || return
    while IFS= read -r line; do
        [[ $line == *': /'* ]] || continue
        OWN[/${line#*: /}]=${line%%: /*}
    done < <(printf '%s\0' "${Q[@]}" | xargs -0 dpkg -S -- 2>/dev/null)
}
ownerof() { OWNP=${OWN[${CAN[$1]}]}; }

scan_files() {
    say "Scanning /opt, /usr/local and launchers..."
    FP=() FK=() FSEEN=() OWN=() CAN=()
    local p d h i k reason e
    local -a DEXS=() DD=(/usr/share/applications /usr/local/share/applications /root/Desktop /root/.local/share/applications)
    for p in /opt/*; do
        [[ -e $p || -L $p ]] || continue
        case $p in /opt/CyberPatriot*|/opt/cyberpatriot*) continue ;; esac
        fadd opt "$p"
    done
    for d in /usr/local/bin /usr/local/sbin /usr/local/games /usr/games; do
        [[ -d $d ]] || continue
        while IFS= read -r -d '' p; do fadd bin "$p"; done \
            < <(find "$d" -mindepth 1 -maxdepth 1 '(' -type f -o -type l ')' -print0 2>/dev/null)
    done
    for h in /home/*; do DD+=("$h/Desktop" "$h/.local/share/applications"); done
    for d in "${DD[@]}"; do
        [[ -d $d ]] || continue
        while IFS= read -r -d '' p; do fadd desk "$p"; done \
            < <(find "$d" -maxdepth 1 '(' -type f -o -type l ')' -name '*.desktop' -print0 2>/dev/null)
    done
    local -a DX=()
    for i in "${!FP[@]}"; do
        DX[i]=""
        if [[ ${FK[i]} == desk ]]; then desk_exec "${FP[i]}"; DX[i]=$DEX; [[ -n $DEX ]] && DEXS+=("$DEX"); fi
    done
    own_lookup "${FP[@]}" "${DEXS[@]}"
    for i in "${!FP[@]}"; do
        p=${FP[i]}
        ownerof "$p"; [[ -n $OWNP ]] && continue          # owned by a package: the package row covers it
        case ${FK[i]} in
            opt)  reason="unpackaged software in /opt" ;;
            bin)  reason="unpackaged file in ${p%/*}" ;;
            desk)
                desk_exec "$p"
                reason="launcher not from a package: Exec=${DEXF:0:60}"
                if [[ -n ${DX[i]} ]]; then ownerof "${DX[i]}"; [[ -n $OWNP ]] && reason+=" (${OWNP%%,*})"; fi ;;
        esac
        e=$(stat -c %Y -- "$p" 2>/dev/null)
        if [[ -n $e ]]; then printf -v D '%(%F)T' "$e"; else D=-; fi
        emit FILE file - "$D" - "$reason" "$p"
    done
}

load_items() {
    NM=() CT=() SRC=() VER=() DT=() EX=() WH=() STT=() QP=()
    local tmp cn c s v d x w n
    tmp=$(mktemp) || return 1
    { scan_pkgs; scan_xpkg; scan_files; } >"$tmp"
    while IFS='|' read -r -d '' cn c s v d x w n; do
        NM+=("$n") CT+=("$c") SRC+=("$s") VER+=("$v") DT+=("$d") EX+=("$x") WH+=("$w") STT+=("") QP+=("")
    done < <(LC_ALL=C sort -z -t '|' -k1,1n -k8 "$tmp")
    rm -f "$tmp"
}

# ---------- drawing ----------
draw() {
    local W=$COLUMNS i row idx buf c
    LH=$((LINES - 5)); ((LH < 1)) && LH=1
    clamp
    local nu=${#VIEW[@]} nm=${#MARK[@]}

    local left=" Package Auditor" right sp
    right="H:${CNT[HACK]:-0} S:${CNT[SERVER]:-0} G:${CNT[GAME]:-0} P:${CNT[P2P]:-0} N:${CNT[NEW]:-0} X:${CNT[XPKG]:-0} F:${CNT[FILE]:-0} $SEP $nm marked "
    [[ -n $CATF ]] && right="[$CATF] $right"
    [[ -n $FILTER ]] && right="[/$FILTER] $right"
    printf -v sp '%*s' $((W - ${#left} - ${#right} > 0 ? W - ${#left} - ${#right} : 1)) ''
    buf=$'\e[H\e[1;97;44m'"${left}${sp}${right}"$'\e[0m\e[K\n'

    local verw=12 namew reasonw
    namew=$(((W - 25 - 14) * 45 / 100)); ((namew < 12)) && namew=12
    reasonw=$((W - 25 - namew - 1 - verw - 1)); ((reasonw < 0)) && reasonw=0
    local hdr
    printf -v hdr ' %s %-6s %-7s %-6s %-*s %-*s %s' ' ' CAT SRC STATE "$namew" NAME "$verw" VERSION REASON
    buf+=$'\e[1;36m'"${hdr:0:W}"$'\e[0m\e[K\n'

    for ((row = 0; row < LH; row++)); do
        idx=$((TOP + row))
        if ((idx >= nu)); then
            if ((nu == 0 && row == 0)); then buf+=$'\e[2m  (no findings - press s to scan)\e[0m\e[K\n'; else buf+=$'\e[K\n'; fi
            continue
        fi
        i=${VIEW[idx]}; c=${CT[i]}
        local base=$'\e[39m' pre="" catc=${CATC[$c]} st=${STT[i]} stc="" part pad
        iskept "$i" && [[ -z $st ]] && st=KEEP
        ((idx == CUR)) && { pre=$'\e[48;5;24m'; base=$'\e[97m'; }
        if [[ -n $st ]]; then
            base=$'\e[90m'; catc=90
            case $st in QUAR) stc=$'\e[33m' ;; KEEP) stc=$'\e[32m' ;; *) stc=$'\e[31m' ;; esac
        fi
        local mk=" "; [[ -n ${MARK[$i]} ]] && mk="$MK"
        local line="$pre$base "
        line+=$'\e[92m'"$mk$base "
        printf -v part '%-6s' "$c"; line+=$'\e['"$catc"'m'"$part$base "
        printf -v part '%-7s ' "${SRC[i]}"; line+="$part"
        printf -v part '%-6s' "$st"; line+="$stc$part$base "
        ltrunc "${NM[i]}" "$namew"; printf -v pad '%*s' $((namew - ${#LT})) ''; line+="$LT$pad "
        printf -v part '%-*.*s ' "$verw" "$verw" "${VER[i]}"; line+="$part"
        ltrunc "${WH[i]}" "$reasonw"; line+="$LT"
        buf+="$line"$'\e[0m\e[K\n'
    done

    local info=""
    ((TOP > 0)) && info+=" $UP_ARR more "
    ((TOP + LH < nu)) && info+=" $DN_ARR more "
    local rule; printf -v rule '%*s' $((W - ${#info})) ''
    buf+=$'\e[2m'"${rule// /$HR}${info}"$'\e[0m\e[K\n'

    local stt=$ST sc=$SC
    if [[ -z $stt && $nu -gt 0 ]]; then
        i=${VIEW[CUR]}; stt="${NM[i]}  ${WH[i]}  [${DT[i]}]"; sc=36
    fi
    stt=${stt//[[:cntrl:]]/?}
    buf+=$'\e['"$sc"'m '"${stt:0:W-2}"$'\e[0m\e[K\n'

    local -a hints=("$KUD:move" "Space:mark" "p:purge" "x:quarantine" "K:keep" "v:inspect" "0-7:filter" "s:scan" "R:report" "?:help" "q:quit")
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
        "  Space              mark / unmark       a  mark all visible   A  clear marks"
        "  Enter  v           inspect: status, install date + command, reverse deps, units, launchers"
        "  p                  PURGE marked (or highlighted): apt is simulated first, you review it,"
        "                     extras / protected / browser-or-office packages need typing PURGE"
        "  r                  apt autoremove --purge (simulated and reviewed the same way)"
        "  x  u               quarantine / restore unpackaged FILE rows -> $QROOT"
        "  K                  toggle KEEP (README says it's authorized); saved to $KEEPFILE"
        "  B                  export the installed package list as a baseline (run on a clean VM)"
        "  0-7                filter: 0 all, 1 hack, 2 server, 3 game, 4 p2p, 5 new, 6 snap/flatpak, 7 files"
        "  /                  filter by text      Esc clears filter"
        "  s                  rescan              L  view session log    R  write Markdown report"
        "  ?                  help                q  quit"
        ""
        "Categories: HACK tools, SERVER daemons (may be required!), GAME, P2P/remote access,"
        "NEW = manually installed and not in the clean baseline, XPKG = snap/flatpak, FILE = unpackaged"
        "files in /opt, /usr/local, /usr/games and launchers that no package owns."
        "KEEP rows and protected packages are never removed. Every change asks first."
        "Log: $LOGFILE"
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
            ?) [[ $KEY == [[:print:]] ]] && s+=$KEY ;;
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
targets() {  # targets state -> TG: marked visible items in that state (not kept), else the cursor item
    TG=(); local i
    for i in "${VIEW[@]}"; do [[ -n ${MARK[$i]} && ${STT[i]} == "$1" ]] && ! iskept "$i" && TG+=("$i"); done
    if ((${#TG[@]} == 0 && ${#VIEW[@]} > 0)); then
        i=${VIEW[CUR]}; [[ ${STT[i]} == "$1" ]] && ! iskept "$i" && TG=("$i")
    fi
}

record() {  # record action target version extra rc cat
    A_TM+=("$(date +%T)") A_ACT+=("$1") A_TG+=("$2") A_VER+=("${3:--}") A_XT+=("${4:--}") A_RC+=("${5:-0}") A_CT+=("${6:--}")
    log OK "$1 [$6] $2 ver=${3:--} rc=${5:-0} ${4:+note=$4}"
}

act_scan() {
    MARK=(); TOP=0; CUR=0
    load_baseline
    load_keep
    load_items; build_view
    log INFO "scan base=$BASEMODE($BASECNT) found=${#NM[@]} hack=${CNT[HACK]} server=${CNT[SERVER]} game=${CNT[GAME]} p2p=${CNT[P2P]} new=${CNT[NEW]} xpkg=${CNT[XPKG]} file=${CNT[FILE]}"
    ST="Found ${#NM[@]} item(s). Baseline: $BASEDESC ($BASECNT)"; SC=36
}

# Simulate an apt removal and prepare a review file.
# apt_review purge names... | apt_review autoremove  ->  PLAN[] WARN PFILE ; returns 1 if the simulation failed
apt_review() {
    local mode=$1; shift
    local out rc tag n w
    local -A sel=()
    local -a extra=() prot=() soft=() kept=()
    for n in "$@"; do sel[$n]=1; done
    if [[ $mode == purge ]]; then out=$(apt-get -s purge -- "$@" 2>&1); rc=$?
    else out=$(apt-get -s autoremove --purge 2>&1); rc=$?; fi
    PLAN=(); WARN=""
    while read -r tag n _; do
        [[ $tag == Purg || $tag == Remv ]] && PLAN+=("${n%%:*}")
    done <<<"$out"
    for n in "${PLAN[@]}"; do
        [[ $mode == purge && -z ${sel[$n]} ]] && extra+=("$n")
        is_prot "$n" && prot+=("$n")
        is_soft "$n" && soft+=("$n")
        [[ -n ${KEEP[$n]} ]] && kept+=("$n")
    done
    ((${#extra[@]})) && WARN+="${#extra[@]} EXTRA package(s) beyond your selection: ${extra[*]}. "
    ((${#prot[@]})) && WARN+="PROTECTED/system: ${prot[*]}. "
    ((${#soft[@]})) && WARN+="Browser/office (often required by the README): ${soft[*]}. "
    ((${#kept[@]})) && WARN+="On your KEEP list: ${kept[*]}. "
    ((${#PLAN[@]} > 10)) && WARN+="${#PLAN[@]} packages would be removed. "
    PFILE=$(mktemp) || return 1
    {
        if [[ $mode == purge ]]; then echo "SIMULATION: apt-get -s purge -- $*"; else echo "SIMULATION: apt-get -s autoremove --purge"; fi
        echo
        if ((rc != 0)); then echo "!! SIMULATION FAILED (exit $rc) - nothing will be run"; else
            echo "Would remove ${#PLAN[@]} package(s):"
            printf '  %s\n' "${PLAN[@]}"
        fi
        echo
        if [[ -n $WARN ]]; then echo "!! WARNINGS"; echo "   $WARN"; else echo "No warnings: only the selected packages are affected."; fi
        echo
        echo "---- raw apt output ----"
        echo "$out"
    } >"$PFILE"
    log INFO "simulate $mode rc=$rc plan=${PLAN[*]} warn=${WARN:+yes}"
    ((rc == 0))
}

apt_refresh() {  # marks apt rows that are no longer installed as PURGED -> GONE[]
    GONE=(); local st n i
    local -A inst=()
    while read -r st n; do [[ $st == ii ]] && inst[${n%%:*}]=1; done \
        < <(dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 2>/dev/null)
    for i in "${!NM[@]}"; do
        [[ ${SRC[i]} == apt && -z ${STT[i]} && -z ${inst[${NM[i]}]} ]] && { STT[i]=PURGED; GONE+=("$i"); }
    done
}

purge_apt() {  # purge_apt idx...
    local -a idx=("$@") sel=() names=()
    local i rc n
    choose "APT PURGE ${#idx[@]} package(s) - [a]ll / [o]ne-by-one / [n]o  (a simulation comes next)" || { ST="Cancelled"; SC=33; return; }
    for i in "${idx[@]}"; do
        if [[ $CH == o ]]; then
            ltrunc "[${CT[i]}] ${NM[i]} ${VER[i]} - ${WH[i]}" $((COLUMNS - 20))
            ynq "$LT"; rc=$?
            ((rc == 2)) && break
            ((rc == 1)) && continue
        fi
        sel+=("$i"); names+=("${NM[i]}")
    done
    ((${#sel[@]})) || { ST="Nothing selected"; SC=33; return; }
    say "Simulating apt-get purge..."
    apt_review purge "${names[@]}"; rc=$?
    pager "$PFILE"; rm -f "$PFILE"
    ((rc == 0)) || { ST="Simulation failed - nothing removed (see log)"; SC=31; return; }
    ((${#PLAN[@]})) || { ST="apt reports nothing to remove"; SC=33; return; }
    if [[ -n $WARN ]]; then
        prompt "Warnings were shown. Type PURGE to continue:" 0 && [[ $PVAL == PURGE ]] || { ST="Cancelled"; SC=33; return; }
    else
        confirm "Run apt-get purge on ${#names[@]} package(s) (${#PLAN[@]} total)?" n || { ST="Cancelled"; SC=33; return; }
    fi
    log CMD "apt-get purge -y -- ${names[*]}"
    run_visible env DEBIAN_FRONTEND=noninteractive apt-get purge -y -- "${names[@]}"
    rc=$RC
    apt_refresh
    local -A sels=() gone=()
    for i in "${sel[@]}"; do sels[$i]=1; done
    local ok=0 fail=0
    for i in "${GONE[@]}"; do
        gone[${NM[i]}]=1
        if [[ -n ${sels[$i]} ]]; then record purge "${NM[i]}" "${VER[i]}" "" "$rc" "${CT[i]}"; ((ok++)); unset 'MARK[$i]'
        else record "purge (dependency)" "${NM[i]}" "${VER[i]}" "removed with selection" "$rc" "${CT[i]}"; fi
    done
    local -a other=()
    for n in "${PLAN[@]}"; do [[ -z ${gone[$n]} ]] && ! printf '%s\n' "${names[@]}" | grep -qxF -- "$n" && other+=("$n"); done
    ((${#other[@]})) && record "purge (dependency)" "${other[*]}" - "not in findings list" "$rc" -
    for i in "${sel[@]}"; do [[ -z ${STT[i]} ]] && { ((fail++)); log FAIL "still installed after purge: ${NM[i]}"; }; done
    build_view
    if ((fail == 0)); then ST="Purged $ok package(s) (apt exit $rc)"; SC=32
    else ST="Purged $ok, $fail still installed (apt exit $rc) - see log"; SC=31; fi
    if confirm "Check for leftover autoremovable packages?" y; then act_autoremove; fi
}

act_autoremove() {
    local rc i
    say "Simulating apt-get autoremove --purge..."
    apt_review autoremove; rc=$?
    ((rc == 0)) || { pager "$PFILE"; rm -f "$PFILE"; ST="Simulation failed (see log)"; SC=31; return; }
    if ((${#PLAN[@]} == 0)); then rm -f "$PFILE"; ST="Nothing to autoremove"; SC=36; return; fi
    pager "$PFILE"; rm -f "$PFILE"
    if [[ -n $WARN ]]; then
        prompt "Warnings were shown. Type PURGE to continue:" 0 && [[ $PVAL == PURGE ]] || { ST="Cancelled"; SC=33; return; }
    else
        confirm "Run apt-get autoremove --purge (${#PLAN[@]} package(s))?" n || { ST="Cancelled"; SC=33; return; }
    fi
    log CMD "apt-get autoremove --purge -y : ${PLAN[*]}"
    local -a plan=("${PLAN[@]}")
    run_visible env DEBIAN_FRONTEND=noninteractive apt-get autoremove --purge -y
    rc=$RC
    apt_refresh
    for i in "${GONE[@]}"; do record autoremove "${NM[i]}" "${VER[i]}" "" "$rc" "${CT[i]}"; done
    record autoremove "${plan[*]}" - "all packages in this run" "$rc" -
    build_view
    ST="Autoremove finished (apt exit $rc), ${#plan[@]} package(s) planned"; SC=$((rc == 0 ? 32 : 31))
}

xcmd() {  # xcmd idx -> XC (command array to remove a snap / flatpak); returns 1 if the name is invalid
    local i=$1 u h
    XC=()
    case ${SRC[i]} in
        snap)    [[ ${NM[i]} =~ $SNAP_RE ]] || return 1; XC=(snap remove --purge "${NM[i]}") ;;
        flatpak) [[ ${NM[i]} =~ $FLAT_RE ]] || return 1
                 if [[ ${EX[i]} == system ]]; then XC=(flatpak uninstall -y --delete-data "${NM[i]}")
                 else
                     u=${EX[i]}; IFS=: read -r _ _ _ _ _ h _ < <(getent passwd "$u")
                     [[ -n $h ]] || return 1
                     XC=(runuser -u "$u" -- env HOME="$h" flatpak --user uninstall -y --delete-data "${NM[i]}")
                 fi ;;
        *) return 1 ;;
    esac
}

purge_x() {  # purge_x idx...  (snap / flatpak: no dry-run, so show the exact commands first)
    local -a idx=("$@") sel=()
    local i rc pf
    choose "REMOVE ${#idx[@]} snap/flatpak app(s) - [a]ll / [o]ne-by-one / [n]o  (exact commands shown next)" || { ST="Cancelled"; SC=33; return; }
    pf=$(mktemp) || return
    echo "These commands will be run (snap/flatpak have no dry-run):" >"$pf"; echo >>"$pf"
    for i in "${idx[@]}"; do
        if [[ $CH == o ]]; then
            ltrunc "[${SRC[i]}] ${NM[i]} ${EX[i]}" $((COLUMNS - 20))
            ynq "$LT"; rc=$?
            ((rc == 2)) && break
            ((rc == 1)) && continue
        fi
        xcmd "$i" || { log FAIL "invalid snap/flatpak name or user: ${NM[i]}"; continue; }
        sel+=("$i"); echo "  ${XC[*]}" >>"$pf"
    done
    if ((${#sel[@]} == 0)); then rm -f "$pf"; ST="Nothing selected"; SC=33; return; fi
    pager "$pf"; rm -f "$pf"
    confirm "Run ${#sel[@]} removal command(s)?" n || { ST="Cancelled"; SC=33; return; }
    local -A rcs=()
    restore_term
    for i in "${sel[@]}"; do
        xcmd "$i"
        printf '\n\e[1;36m$ %s\e[0m\n' "${XC[*]}"
        log CMD "${XC[*]}"
        "${XC[@]}"; rcs[$i]=$?
    done
    printf '\n\e[1;36m[done] press any key\e[0m'; IFS= read -rsn1 _
    init_term
    local ok=0 fail=0
    for i in "${sel[@]}"; do
        if ((rcs[$i] == 0)); then STT[i]=PURGED; record "remove (${SRC[i]})" "${NM[i]}" "${VER[i]}" "" 0 "${CT[i]}"; ((ok++)); unset 'MARK[$i]'
        else ((fail++)); log FAIL "remove ${SRC[i]} ${NM[i]} rc=${rcs[$i]}"; fi
    done
    build_view
    if ((fail == 0)); then ST="Removed $ok app(s)"; SC=32; else ST="Removed $ok, $fail failed - see log"; SC=31; fi
}

act_purge() {
    targets ""
    ((${#TG[@]})) || { ST="Nothing to purge here (kept, already handled, or nothing selected)"; SC=33; return; }
    local -a ap=() ox=()
    local i nf=0 np=0 ni=0 note=""
    for i in "${TG[@]}"; do
        case ${SRC[i]} in
            apt)
                if ! [[ ${NM[i]} =~ $NAME_RE ]]; then ((ni++)); log FAIL "invalid package name skipped: ${NM[i]}"
                elif is_prot "${NM[i]}"; then ((np++)); log INFO "refused protected package ${NM[i]}"
                else ap+=("$i"); fi ;;
            file) ((nf++)) ;;
            *) ox+=("$i") ;;
        esac
    done
    ((nf)) && note+=" $nf file row(s) skipped (use x)."
    ((np)) && note+=" $np protected package(s) refused."
    ((ni)) && note+=" $ni invalid name(s) skipped."
    ST=""
    ((${#ap[@]})) && purge_apt "${ap[@]}"
    ((${#ox[@]})) && purge_x "${ox[@]}"
    if ((${#ap[@]} == 0 && ${#ox[@]} == 0)); then ST="Nothing purged.$note"; SC=33
    elif [[ -n $note ]]; then ST+=" -$note"; fi
}

remove_one() {  # remove_one idx -> quarantine a FILE row ; 0 ok ; sets LASTERR
    local i=$1 p=${NM[$1]} dest
    LASTERR=""
    case $p in
        ''|/|/opt|/usr|/usr/local|/usr/local/bin|/usr/local/sbin|/usr/games|/usr/local/games|/home|/root|/etc|/var|/tmp)
            LASTERR="refusing protected path"; log FAIL "quarantine $LASTERR $p"; return 1 ;;
    esac
    if [[ ! -e $p && ! -L $p ]]; then LASTERR="no longer exists"; log FAIL "quarantine $LASTERR $p"; return 1; fi
    [[ -d $QROOT ]] || { mkdir -p "$QROOT" && chmod 700 "$QROOT"; }
    dest=$QDIR/${p#/}
    if mkdir -p -- "${dest%/*}" && mv -- "$p" "$dest" 2>/dev/null; then
        QP[i]=$dest; STT[i]=QUAR
    else
        LASTERR="mv failed"; log FAIL "quarantine $p"; return 1
    fi
    record quarantine "$p" - "to $dest" 0 FILE
}

act_quarantine() {
    targets ""
    local -a fl=()
    local i skipped=0
    for i in "${TG[@]}"; do [[ ${SRC[i]} == file ]] && fl+=("$i") || ((skipped++)); done
    ((${#fl[@]})) || { ST="Only unpackaged FILE rows can be quarantined (packages: use p)"; SC=33; return; }
    choose "QUARANTINE ${#fl[@]} file(s) to $QROOT - [a]ll / [o]ne-by-one / [n]o" || { ST="Cancelled"; SC=33; return; }
    local ok=0 fail=0 rc
    for i in "${fl[@]}"; do
        if [[ $CH == o ]]; then
            ltrunc "${NM[i]}  ${WH[i]}" $((COLUMNS - 20))
            ynq "$LT"; rc=$?
            ((rc == 2)) && break
            ((rc == 1)) && continue
        fi
        if remove_one "$i"; then ((ok++)); unset 'MARK[$i]'; else ((fail++)); fi
    done
    build_view
    if ((fail == 0)); then ST="Quarantined $ok file(s) (u restores)"; SC=32; else ST="Quarantined $ok, $fail failed - $LASTERR"; SC=31; fi
    ((skipped)) && ST+=" - $skipped package row(s) skipped"
}

act_restore() {
    targets QUAR
    ((${#TG[@]})) || { ST="Nothing quarantined selected"; SC=33; return; }
    confirm "Restore ${#TG[@]} item(s) to original paths?" n || { ST="Cancelled"; SC=33; return; }
    local i p ok=0 fail=0
    for i in "${TG[@]}"; do
        p=${NM[i]}
        if [[ -e $p || -L $p ]]; then LASTERR="original path exists: ${p##*/}"; log FAIL "restore $LASTERR"; ((fail++)); continue; fi
        if mkdir -p -- "${p%/*}" && mv -- "${QP[i]}" "$p" 2>/dev/null; then
            STT[i]=""; QP[i]=""; record restore "$p" - "" 0 FILE; ((ok++)); unset 'MARK[$i]'
        else
            LASTERR="mv failed"; log FAIL "restore $p"; ((fail++))
        fi
    done
    build_view
    if ((fail == 0)); then ST="Restored $ok item(s)"; SC=32; else ST="Restored $ok, $fail failed - $LASTERR"; SC=31; fi
}

act_keep() {
    ((${#VIEW[@]})) || return
    local i=${VIEW[CUR]} n=${NM[${VIEW[CUR]}]}
    if [[ -n ${KEEP[$n]} ]]; then
        unset 'KEEP[$n]'; ST="Removed from keep list: $n"; SC=33; log INFO "keep-off $n"
    else
        KEEP[$n]=1; unset 'MARK[$i]'; ST="KEEP (authorized, never touched): $n"; SC=32; log INFO "keep-on $n"
    fi
    save_keep || { ST="Cannot write $KEEPFILE"; SC=31; }
    recount
}

act_baseline() {
    local def out st n
    def=/root/pkgaudit-baseline-$(date +%Y%m%d-%H%M).txt
    prompt "Save baseline of installed packages to:" 0 "$def" || { ST="Cancelled"; SC=33; return; }
    out=$PVAL; [[ -z $out ]] && return
    if [[ -e $out ]]; then confirm "$out exists. Overwrite?" n || { ST="Cancelled"; SC=33; return; }; fi
    {
        while read -r st n; do [[ $st == ii ]] && echo "${n%%:*}"; done \
            < <(dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 2>/dev/null) | sort -u
    } >"$out" 2>/dev/null || { ST="Cannot write $out"; SC=31; return; }
    log INFO "baseline exported: $out"
    ST="Baseline saved ($(wc -l <"$out") packages): $out  (use --baseline)"; SC=32
}

act_view() {
    ((${#VIEW[@]})) || return
    local i=${VIEW[CUR]} n l t re
    n=${NM[i]}
    if [[ ${SRC[i]} == apt && ! $n =~ $NAME_RE ]]; then ST="Invalid package name"; SC=31; return; fi
    t=$(mktemp) || return
    {
        printf 'Name : %s\nCat  : %s (%s)\nWhy  : %s\nVer  : %s\nDate : %s\nState: %s\n\n' "${n//[[:cntrl:]]/?}" "${CT[i]}" "${SRC[i]}" "${WH[i]}" "${VER[i]}" "${DT[i]}" "${STT[i]:-present}"
        is_prot "$n" && echo "NOTE: protected/system package - purge is refused here."
        is_soft "$n" && echo "NOTE: browser/office package - often required by the README."
        iskept "$i" && echo "NOTE: on your KEEP list."
        case ${SRC[i]} in
            apt)
                echo "--- dpkg status ---"; dpkg -s "$n" 2>&1 | head -n 20
                echo; echo "--- who installed it (apt history.log) ---"
                re=${n//./\\.}; re=${re//+/\\+}
                zcat -f /var/log/apt/history.log* 2>/dev/null | grep -hE -B3 "^Install: (.*, )?$re:" | grep -E '^(Start-Date|Commandline|Requested-By|Install)' | cut -c1-160
                echo; echo "--- installed packages that depend on it ---"
                apt-cache rdepends --installed "$n" 2>/dev/null | tail -n +2 | head -n 30
                echo; echo "--- systemd units / launchers shipped ---"
                dpkg -L "$n" 2>/dev/null | grep -E '\.(service|desktop)$' | while IFS= read -r l; do
                    if [[ $l == *.service ]] && command -v systemctl >/dev/null; then
                        printf '%s  [%s]\n' "$l" "$(systemctl is-active "${l##*/}" 2>/dev/null)"
                    else echo "$l"; fi
                done
                echo; echo "--- files (first 40) ---"; dpkg -L "$n" 2>/dev/null | head -n 40 ;;
            snap)    snap info "$n" 2>&1 | head -n 30 ;;
            flatpak) flatpak info "$n" 2>&1 | head -n 30 ;;
            file)
                stat -- "$n"
                command -v file >/dev/null && file -- "$n"
                echo
                if [[ -d $n ]]; then ls -la -- "$n" | head -50
                elif grep -qI . -- "$n" 2>/dev/null; then echo "--- head ---"; head -n 25 -- "$n" | cut -c1-200; fi ;;
        esac
    } >"$t" 2>&1
    pager "$t"; rm -f "$t"
}

act_report() {
    local dir def out
    if [[ -n $SUDO_USER && -d /home/$SUDO_USER/Desktop ]]; then dir=/home/$SUDO_USER/Desktop
    elif [[ -n $SUDO_USER && -d /home/$SUDO_USER ]]; then dir=/home/$SUDO_USER
    else dir=/root; fi
    def=$dir/pkgaudit-report-$(date +%Y%m%d-%H%M).md
    prompt "Report path:" 0 "$def" || { ST="Cancelled"; SC=33; return; }
    out=$PVAL; [[ -z $out ]] && return
    if [[ -e $out ]]; then confirm "$out exists. Overwrite?" n || { ST="Cancelled"; SC=33; return; }; fi
    if ! write_report >"$out" 2>/dev/null; then ST="Cannot write $out"; SC=31; return; fi
    [[ -n $SUDO_USER ]] && chown "$SUDO_USER" "$out" 2>/dev/null
    REPN=${#A_ACT[@]}
    log INFO "report written: $out"
    ST="Report saved: $out"; SC=32
}

write_report() {
    local i k c n p
    echo "# CyberPatriot Package Audit Report"
    echo
    printf -- '- **Host:** %s\n- **Date:** %s\n- **Operator:** %s\n' "$(hostname)" "$(date '+%F %T')" "${SUDO_USER:-root}"
    printf -- '- **Baseline:** %s (%s entries)\n- **Keep list:** `%s`\n- **Quarantine folder:** `%s`\n- **Log:** `%s`\n\n' "$BASEDESC" "$BASECNT" "$KEEPFILE" "$QDIR" "$LOGFILE"
    echo "## Summary"
    echo
    echo "| Category | Removed this session | Quarantined | Kept (README) | Still flagged |"
    echo "|---|---:|---:|---:|---:|"
    for c in "${CATS[@]}"; do
        local rm=0 q=0 kp=0 rem=0
        for k in "${!A_ACT[@]}"; do
            [[ ${A_CT[k]} == "$c" && ( ${A_ACT[k]} == purge* || ${A_ACT[k]} == autoremove || ${A_ACT[k]} == remove* ) ]] && ((rm++))
        done
        for i in "${!NM[@]}"; do
            [[ ${CT[i]} == "$c" ]] || continue
            if [[ ${STT[i]} == QUAR ]]; then ((q++))
            elif [[ -z ${STT[i]} ]]; then if iskept "$i"; then ((kp++)); else ((rem++)); fi; fi
        done
        echo "| $c | $rm | $q | $kp | $rem |"
    done
    echo
    echo "## Actions taken"
    echo
    if ((${#A_ACT[@]} == 0)); then echo "_None._"; else
        echo "| Time | Action | Category | Target | Version | Note | Exit |"
        echo "|---|---|---|---|---|---|---:|"
        for k in "${!A_ACT[@]}"; do
            md "${A_TG[k]}"; p=$MD; md "${A_XT[k]}"
            echo "| ${A_TM[k]} | ${A_ACT[k]} | ${A_CT[k]} | \`$p\` | ${A_VER[k]} | $MD | ${A_RC[k]} |"
        done
    fi
    echo
    echo "## Kept as authorized (README)"
    echo
    if ((${#KEEP[@]} == 0)); then echo "_None._"; else
        while IFS= read -r n; do md "$n"; echo "- \`$MD\`"; done < <(printf '%s\n' "${!KEEP[@]}" | sort)
    fi
    echo
    echo "## Quarantined files (not deleted)"
    echo
    n=0
    for i in "${!NM[@]}"; do
        [[ ${STT[i]} == QUAR ]] || continue
        ((n++ == 0)) && { echo "| Original path | Now at |"; echo "|---|---|"; }
        md "${NM[i]}"; p=$MD; md "${QP[i]}"
        echo "| \`$p\` | \`$MD\` |"
    done
    ((n)) || echo "_None._"
    echo
    echo "Restore with \`u\` inside pkgaudit, or \`sudo mv <now-at> <original>\`. Delete the quarantine folder when finished."
    echo
    echo "## Remaining findings (reviewed, not removed)"
    echo
    n=0
    for i in "${!NM[@]}"; do
        [[ -z ${STT[i]} ]] && ! iskept "$i" || continue
        ((n++ == 0)) && { echo "| Category | Source | Name | Version | Installed | Why |"; echo "|---|---|---|---|---|---|"; }
        md "${NM[i]}"; p=$MD; md "${WH[i]}"
        echo "| ${CT[i]} | ${SRC[i]} | \`$p\` | ${VER[i]} | ${DT[i]} | $MD |"
    done
    ((n)) || echo "_None._"
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
            UP|k)   ((CUR > 0)) && ((CUR--)) ;;
            DOWN|j) ((CUR < n - 1)) && ((CUR++)) ;;
            PGUP)   CUR=$((CUR - LH + 1)); ((CUR < 0)) && CUR=0 ;;
            PGDN)   CUR=$((CUR + LH - 1)); ((CUR > n - 1)) && CUR=$((n - 1)) ;;
            HOME|g) CUR=0 ;;
            END|G)  CUR=$((n - 1)) ;;
            ' ')    if ((n)); then
                        k=${VIEW[CUR]}
                        if [[ -n ${MARK[$k]} ]]; then unset 'MARK[$k]'; elif ! iskept "$k"; then MARK[$k]=1; fi
                        ((CUR < n - 1)) && ((CUR++))
                    fi ;;
            a)      for k in "${VIEW[@]}"; do iskept "$k" || [[ -n ${STT[k]} ]] || MARK[$k]=1; done ;;
            A)      MARK=() ;;
            ENTER|v) act_view ;;
            p|D|DEL) act_purge ;;
            r)      act_autoremove ;;
            x)      act_quarantine ;;
            u)      act_restore ;;
            K)      act_keep ;;
            B)      act_baseline ;;
            [0-7])  if [[ $KEY == 0 ]]; then CATF=""; else CATF=${CATS[KEY - 1]}; fi
                    build_view; ST="Category: ${CATF:-all}"; SC=36 ;;
            '/')    if prompt "Filter:" 0 "$FILTER"; then FILTER=$PVAL; build_view; fi ;;
            s)      act_scan ;;
            L)      pager +G "$LOGFILE" ;;
            R)      act_report ;;
            '?')    show_help ;;
            ESC)    if [[ -n $FILTER ]]; then FILTER=""; build_view; fi ;;
            q|Q)    if ((${#A_ACT[@]} > REPN)); then
                        confirm "Write report before quitting?" y && act_report
                    fi
                    return ;;
        esac
        clamp
    done
}

trap 'restore_term; exit 0' EXIT
trap 'exit 130' INT TERM
trap ':' WINCH

touch "$LOGFILE" 2>/dev/null && chmod 600 "$LOGFILE" 2>/dev/null
init_term
get_size
log START "session start (invoked by ${SUDO_USER:-root})"
act_scan
main_loop
log END "session end"
