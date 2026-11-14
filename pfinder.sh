#!/usr/bin/env bash
# pfinder.sh - keyboard-driven prohibited-file finder for CyberPatriot (Linux Mint 21)
# Pure bash + find/grep/stat/du/sort/less. Run with: sudo ./pfinder.sh
# Press ? inside for keybinds. R writes a Markdown post-round report.

LOGFILE=/var/log/pfinder.log
QROOT=/root/pfinder-quarantine
QDIR=$QROOT/$(date +%Y%m%d-%H%M%S)

if [[ $EUID -ne 0 ]]; then
    echo "pfinder: must be run as root (try: sudo $0)" >&2
    exit 1
fi
if [[ ! -t 0 || ! -t 1 ]]; then
    echo "pfinder: needs an interactive terminal" >&2
    exit 1
fi
for c in find grep stat du sort sha256sum less mktemp xargs stty; do
    command -v "$c" >/dev/null || { echo "pfinder: missing command: $c" >&2; exit 1; }
done

# ---------- glyphs ----------
if [[ ${LC_ALL:-${LC_CTYPE:-$LANG}} == *[Uu][Tt][Ff]* ]]; then
    HR='─' MK='●' KUD='↑↓' UP_ARR='↑' DN_ARR='↓' SEP='·' ELL='…'
else
    HR='-' MK='*' KUD='Up/Dn' UP_ARR='^' DN_ARR='v' SEP='|' ELL='~'
fi

# ---------- state ----------
CATS=(MEDIA GAME PWLIST SCRIPT SENSTV)
declare -A CATN=([MEDIA]=1 [GAME]=2 [PWLIST]=3 [SCRIPT]=4 [SENSTV]=5)
declare -A CATC=([MEDIA]='35' [GAME]='32' [PWLIST]='91' [SCRIPT]='1;91' [SENSTV]='33')
declare -A CNT=() MARK=()
TY=() OW=() SZ=() HSZ=() CT=() WH=() PTH=() STT=() QP=()      # one entry per finding
A_TM=() A_ACT=() A_IDX=() A_SHA=()                              # actions taken (for report)
VIEW=()
CUR=0 TOP=0 LH=10 REPN=0
FILTER="" CATF="" HID=0
ST="" SC=32
KEY="" PVAL="" TG=() LT="" HS="" CH="" LASTERR="" KW=""
SAVED_STTY=""
ROOTS=(/home /root /tmp /var/tmp /dev/shm /opt /srv /var/www /media /mnt /usr/games /usr/share/games)
FR=()

EXTM='mp3 mp4 avi mkv mov wmv flv webm m4a m4v aac flac ogg wav wma mpg mpeg 3gp'
EXTR='nes sfc smc gba gb gbc n64 z64 nds'
SCRPAT='/dev/tcp/|(^|[ ;|&`(])(nc|ncat|netcat|socat) |bash -i|mkfifo|pty\.spawn|base64 +-d *\| *(ba)?sh|(curl|wget)[^|]*\| *(ba)?sh|eval *\( *base64_decode|system\(\$_(GET|POST|REQUEST)|socket.*(subprocess|pty|/bin/sh)|(subprocess|pty|/bin/sh).*socket'
SENPAT='password|passwd|credit|\bssn\b|social security|[0-9]{3}-[0-9]{2}-[0-9]{4}'
PR=('(' -path /proc -o -path /sys -o -path /run -o -path /snap -o -name .cache -o -name .mozilla
    -o -path '*/.config/google-chrome' -o -path '*/.config/chromium' -o -path '*/.local/lib'
    -o -name node_modules -o -name site-packages -o -name venv -o -name .venv
    -o -path '/opt/CyberPatriot*' -o -path "$QROOT"
    -o -name 'mkinitramfs*' -o -name 'initramfs*' -o -name 'dracut*' -o -name 'systemd-private-*'
    -o -name 'snap-private-tmp' -o -name '.X11-unix' -o -name '.ICE-unix' -o -name '.font-unix'
    -o -name '.XIM-unix' -o -name '.Test-unix' -o -name 'hsperfdata_*' ')' -prune -o)

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
hsize() {  # hsize bytes -> HS  (pure bash, one decimal)
    local s=$(($1 * 10)) i=0 u=(B K M G T)
    while ((s >= 10240 && i < 4)); do s=$((s / 1024)); ((i++)); done
    if ((i == 0)); then HS="$1B"; else HS="$((s / 10)).$((s % 10))${u[i]}"; fi
}
ltrunc() {  # ltrunc str width -> LT  (sanitised, keeps the tail)
    LT=${1//[[:cntrl:]]/?}
    ((${#LT} > $2)) && LT="$ELL${LT: -$(($2 - 1))}"
}
md() {  # md str -> MD  (safe inside a markdown table cell)
    local bt='`'
    MD=${1//|/\\|}; MD=${MD//"$bt"/\'}; MD=${MD//[[:cntrl:]]/?}
}

# ---------- data ----------
recount() {
    CNT=(); local c i
    for c in "${CATS[@]}"; do CNT[$c]=0; done
    for i in "${!PTH[@]}"; do [[ -z ${STT[i]} ]] && ((CNT[${CT[i]}]++)); done
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
    local cur=-1 i j
    ((${#VIEW[@]})) && cur=${VIEW[CUR]}
    VIEW=()
    for i in "${!PTH[@]}"; do
        [[ -n $CATF && ${CT[i]} != "$CATF" ]] && continue
        [[ -n $FILTER && ${PTH[i],,} != *"${FILTER,,}"* ]] && continue
        VIEW+=("$i")
    done
    CUR=0
    for j in "${!VIEW[@]}"; do [[ ${VIEW[j]} == "$cur" ]] && { CUR=$j; break; }; done
    recount; clamp
}

# ---------- scanning ----------
emit() {  # emit cat why type owner size path   (dedups via $seen)
    [[ -n ${seen[$6]} ]] && return
    seen[$6]=1
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\0' "${CATN[$1]}" "$5" "$3" "$4" "$1" "$2" "$6"
}

names() {  # names ext... -> NE=(-iname *.e -o -iname *.e2 ...)
    NE=(); local e
    for e in "$@"; do NE+=(-o -iname "*.$e"); done
    NE=("${NE[@]:1}")
}

pass_names() {
    local -a M R
    names $EXTM; M=("${NE[@]}")
    names $EXTR; R=("${NE[@]}")
    local F='%y\t%u\t%s\t%p\0'
    find "${FR[@]}" "${PR[@]}" \
        '(' -type d '(' -iname games -o -iname steam -o -iname .steam -o -iname steamapps -o -iname minecraft \
            -o -iname .minecraft -o -iname roms -o -iname 'emulator*' -o -iname '*solitaire*' -o -iname '*doom*' ')' ')' \
            -printf "$F" -prune -o \
        -type f '(' \
            '(' "${M[@]}" ')' -o '(' "${R[@]}" ')' \
            -o '(' -path '/home/*' -size +1M '(' -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' -o -iname '*.gif' ')' ')' \
            -o '(' -iname 'rockyou*' -o -iname '*wordlist*' -o -iname '*passlist*' -o -iname '*password*.txt' \
                -o -iname '*password*.lst' -o -iname '*password*.csv' -o -iname '*.lst' -o -iname john.pot \
                -o -iname '*.potfile' -o -iname '*.hash' -o -iname '*.hashes' -o -iname 'shadow*' -o -iname 'passwd*' ')' \
            -o '(' '(' -path '/tmp/*' -o -path '/var/tmp/*' -o -path '/dev/shm/*' ')' \
                '(' -perm /111 -o -iname '*.sh' -o -iname '*.py' -o -iname '*.pl' -o -iname '*.rb' -o -iname '*.php' \
                    -o -iname '*.elf' -o -iname '*.exe' ')' ')' \
            -o '(' -regex '/\(home/[^/]*\|root\)/\.[^/]*' -perm /111 ')' \
        ')' -printf "$F" 2>/dev/null
}

kwhits() {  # kwhits file -> KW (keywords only, never file contents)
    local f=$1 w r=""
    for w in password passwd credit 'social security'; do
        grep -qiI -e "$w" -- "$f" 2>/dev/null && r+="$w, "
    done
    grep -qiIE -e '\bssn\b' -- "$f" 2>/dev/null && r+="ssn, "
    grep -qIE -e '[0-9]{3}-[0-9]{2}-[0-9]{4}' -- "$f" 2>/dev/null && r+="ssn-pattern, "
    KW=${r%, }
}

scan_emit() {
    local -A seen=()
    local ty ow sz p b lb ext c w
    say "Scanning by name (media, games, password lists, temp scripts)..."
    while IFS=$'\t' read -r -d '' ty ow sz p; do
        b=${p##*/}; lb=${b,,}
        case $lb in readme*|scoringreport*|forensics\ question*) continue ;; esac
        if [[ $ty == d ]]; then
            c=GAME w="dir $b"
            [[ -z $(ls -A -- "$p" 2>/dev/null) ]] && continue   # empty dir, e.g. stock /usr/games
            read -r sz _ < <(du -sb -- "$p" 2>/dev/null)
        else
            ext=${lb##*.}
            case $ext in
                mp3|mp4|avi|mkv|mov|wmv|flv|webm|m4a|m4v|aac|flac|ogg|wav|wma|mpg|mpeg|3gp) c=MEDIA w=".$ext" ;;
                jpg|jpeg|png|gif) c=MEDIA w="large image" ;;
                nes|sfc|smc|gba|gb|gbc|n64|z64|nds) c=GAME w="rom .$ext" ;;
                *) case $lb in
                       rockyou*|*wordlist*|*passlist*|*password*.txt|*password*.lst|*password*.csv|*.lst|john.pot|*.potfile|*.hash|*.hashes|shadow*|passwd*)
                           c=PWLIST w="name $b" ;;
                       *) c=SCRIPT w="script/executable in temp or hidden in home" ;;
                   esac ;;
            esac
        fi
        emit "$c" "$w" "$ty" "$ow" "${sz:-0}" "$p"
    done < <(pass_names)

    say "Scanning script contents for backdoor/reverse-shell patterns..."
    while IFS= read -r -d '' p; do
        read -r ow sz < <(stat -c '%U %s' -- "$p" 2>/dev/null)
        w=$(grep -ioEm1 -e "$SCRPAT" -- "$p" 2>/dev/null | head -c 40)
        w=${w//[$'\t\n']/ }
        emit SCRIPT "matched: $w" f "${ow:-?}" "${sz:-0}" "$p"
    done < <(find "${FR[@]}" "${PR[@]}" -type f -size -1024k \
                '(' -iname '*.sh' -o -iname '*.bash' -o -iname '*.py' -o -iname '*.pl' -o -iname '*.rb' -o -iname '*.php' ')' \
                ! -iname 'pfinder*' ! -iname 'usermgr*' -print0 2>/dev/null \
             | xargs -0 -r grep -lZIE -e "$SCRPAT" 2>/dev/null)

    say "Scanning home directories for sensitive text..."
    local -a HIDE=()
    ((HID)) || HIDE=(! -path '*/.*')
    while IFS= read -r -d '' p; do
        read -r ow sz < <(stat -c '%U %s' -- "$p" 2>/dev/null)
        kwhits "$p"
        emit SENSTV "keyword: $KW" f "${ow:-?}" "${sz:-0}" "$p"
    done < <(find /home /root "${PR[@]}" -type f -size -5120k "${HIDE[@]}" \
                ! -iname 'pfinder*' ! -iname 'README*' ! -iname 'ScoringReport*' ! -iname 'Forensics Question*' \
                -print0 2>/dev/null \
             | xargs -0 -r grep -lZIiE -e "$SENPAT" 2>/dev/null)
}

load_items() {
    TY=() OW=() SZ=() HSZ=() CT=() WH=() PTH=() STT=() QP=()
    local cn sz ty ow c w p
    while IFS=$'\t' read -r -d '' cn sz ty ow c w p; do
        TY+=("$ty") OW+=("$ow") SZ+=("$sz") CT+=("$c") WH+=("$w") PTH+=("$p") STT+=("") QP+=("")
        hsize "$sz"; HSZ+=("$HS")
    done < <(scan_emit | sort -z -t $'\t' -k1,1n -k2,2nr)
}

# ---------- drawing ----------
draw() {
    local W=$COLUMNS i row idx buf c
    LH=$((LINES - 5)); ((LH < 1)) && LH=1
    clamp
    local nu=${#VIEW[@]} nm=0 msz=0
    for i in "${!MARK[@]}"; do ((nm++, msz += SZ[i])); done
    hsize "$msz"

    local left=" Prohibited File Finder" right sp
    right="M:${CNT[MEDIA]:-0} G:${CNT[GAME]:-0} P:${CNT[PWLIST]:-0} S:${CNT[SCRIPT]:-0} T:${CNT[SENSTV]:-0} $SEP $nm marked $HS "
    [[ -n $CATF ]] && right="[$CATF] $right"
    [[ -n $FILTER ]] && right="[/$FILTER] $right"
    printf -v sp '%*s' $((W - ${#left} - ${#right} > 0 ? W - ${#left} - ${#right} : 1)) ''
    buf=$'\e[H\e[1;97;44m'"${left}${sp}${right}"$'\e[0m\e[K\n'

    local hdr
    printf -v hdr ' %s %-6s %-10s %7s %-5s %s' ' ' CAT OWNER SIZE STATE PATH
    buf+=$'\e[1;36m'"${hdr:0:W}"$'\e[0m\e[K\n'

    local pathw=$((W - 35)); ((pathw < 10)) && pathw=10
    for ((row = 0; row < LH; row++)); do
        idx=$((TOP + row))
        if ((idx >= nu)); then
            if ((nu == 0 && row == 0)); then buf+=$'\e[2m  (no findings - press s to scan)\e[0m\e[K\n'; else buf+=$'\e[K\n'; fi
            continue
        fi
        i=${VIEW[idx]}; c=${CT[i]}
        local base=$'\e[39m' pre="" catc=${CATC[$c]} st=${STT[i]} stc=""
        ((idx == CUR)) && { pre=$'\e[48;5;24m'; base=$'\e[97m'; }
        if [[ -n $st ]]; then
            base=$'\e[90m'; catc=90
            [[ $st == QUAR ]] && stc=$'\e[33m' || stc=$'\e[31m'
        fi
        local mk=" "; [[ -n ${MARK[$i]} ]] && mk="$MK"
        local line="$pre$base " part
        line+=$'\e[92m'"$mk$base "
        printf -v part '%-6s' "$c"; line+=$'\e['"$catc"'m'"$part$base "
        printf -v part '%-10.10s %7s ' "${OW[i]}" "${HSZ[i]}"; line+="$part"
        printf -v part '%-5s' "$st"; line+="$stc$part$base "
        ltrunc "${PTH[i]}" "$pathw"; line+="$LT"
        buf+="$line"$'\e[0m\e[K\n'
    done

    local info=""
    ((TOP > 0)) && info+=" $UP_ARR more "
    ((TOP + LH < nu)) && info+=" $DN_ARR more "
    local rule; printf -v rule '%*s' $((W - ${#info})) ''
    buf+=$'\e[2m'"${rule// /$HR}${info}"$'\e[0m\e[K\n'

    local stt=$ST sc=$SC
    if [[ -z $stt && $nu -gt 0 ]]; then
        i=${VIEW[CUR]}; stt="${WH[i]}  ${PTH[i]}"; sc=36
    fi
    stt=${stt//[[:cntrl:]]/?}
    buf+=$'\e['"$sc"'m '"${stt:0:W-2}"$'\e[0m\e[K\n'

    local -a hints=("$KUD:move" "Space:mark" "x:quarantine" "D:delete" "u:restore" "v:view" "0-5:filter" "s:scan" "R:report" "?:help" "q:quit")
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
        "  Enter  v           inspect (stat, file type, matching lines) in a pager"
        "  x                  QUARANTINE marked (or highlighted) -> $QROOT"
        "  D  Del             DELETE permanently  (typing DELETE required for directories)"
        "  u                  restore quarantined items to their original path"
        "  0-5                filter: 0 all, 1 media, 2 games, 3 pw lists, 4 scripts, 5 sensitive text"
        "  /                  filter by path      Esc clears filter"
        "  s                  (re)scan            +  add a scan root"
        "  h                  include hidden files in the sensitive-text scan (rescans)"
        "  L                  view session log    R  write Markdown report"
        "  ?                  help                q  quit"
        ""
        "Every change asks first: [a]ll / [o]ne-by-one / [n]o. Nothing is touched without a yes."
        "Sensitive-text hits list keywords only; the report never contains file contents."
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
    local label=${1//[[:cntrl:]]/?} secret=${2:-0} s=${3:-}
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

targets() {  # targets state -> TG: marked visible items in that state, else the cursor item
    TG=(); local i
    for i in "${VIEW[@]}"; do [[ -n ${MARK[$i]} && ${STT[i]} == "$1" ]] && TG+=("$i"); done
    if ((${#TG[@]} == 0 && ${#VIEW[@]} > 0)); then
        i=${VIEW[CUR]}; [[ ${STT[i]} == "$1" ]] && TG=("$i")
    fi
}

act_scan() {
    local r
    FR=()
    for r in "${ROOTS[@]}"; do [[ -d $r ]] && FR+=("$r"); done
    ((${#FR[@]})) || { ST="No scan roots exist"; SC=31; return; }
    confirm "Scan ${FR[*]} ?" y || { ST="Cancelled"; SC=33; return; }
    MARK=(); TOP=0
    load_items; build_view
    log "scan roots=${FR[*]} hidden=$HID found=${#PTH[@]} media=${CNT[MEDIA]} game=${CNT[GAME]} pwlist=${CNT[PWLIST]} script=${CNT[SCRIPT]} senstv=${CNT[SENSTV]}"
    ST="Found ${#PTH[@]} item(s)"; SC=36
}

record() {  # record action idx sha
    A_TM+=("$(date +%T)") A_ACT+=("$1") A_IDX+=("$2") A_SHA+=("$3")
    log "OK   $1 ${CT[$2]} owner=${OW[$2]} size=${SZ[$2]} sha256=$3 ${PTH[$2]}"
}

remove_one() {  # remove_one idx quarantine|delete -> 0 ok ; sets LASTERR
    local i=$1 mode=$2 p=${PTH[$1]} sha=- dest
    LASTERR=""
    case $p in
        ''|/|/home|/root|/tmp|/var|/var/tmp|/dev/shm|/opt|/srv|/usr|/etc|/boot|/media|/mnt)
            LASTERR="refusing protected path"; log "FAIL $mode $LASTERR $p"; return 1 ;;
    esac
    if [[ ${TY[i]} == d && ${p%/*} == /home ]]; then
        LASTERR="refusing home directory"; log "FAIL $mode $LASTERR $p"; return 1
    fi
    if [[ ! -e $p && ! -L $p ]]; then LASTERR="no longer exists"; log "FAIL $mode $LASTERR $p"; return 1; fi
    [[ ${TY[i]} == f ]] && ((SZ[i] <= 209715200)) && sha=$(sha256sum -- "$p" 2>/dev/null | cut -d' ' -f1)
    if [[ $mode == quarantine ]]; then
        [[ -d $QROOT ]] || { mkdir -p "$QROOT" && chmod 700 "$QROOT"; }
        dest=$QDIR/${p#/}
        if mkdir -p -- "${dest%/*}" && mv -- "$p" "$dest" 2>/dev/null; then
            QP[i]=$dest; STT[i]=QUAR
        else
            LASTERR="mv failed"; log "FAIL quarantine $p"; return 1
        fi
    else
        rm -rf -- "$p" 2>/dev/null
        if [[ -e $p || -L $p ]]; then LASTERR="rm failed"; log "FAIL delete $p"; return 1; fi
        STT[i]=DEL
    fi
    record "$mode" "$i" "$sha"
}

guard() {  # extra approval for directories / items over 1 GiB
    local i=$1 mode=$2
    if [[ $mode == delete && ${TY[i]} == d ]]; then
        prompt "Type DELETE to permanently remove directory ${PTH[i]##*/}:" 0 || return 1
        [[ $PVAL == DELETE ]]; return
    fi
    if ((SZ[i] > 1073741824)); then
        confirm "Large item (${HSZ[i]}): ${PTH[i]##*/}. Proceed?" n; return
    fi
    return 0
}

act_remove() {  # act_remove quarantine|delete
    local mode=$1 verb=QUARANTINE i tot=0 ok=0 fail=0 rc
    [[ $mode == delete ]] && verb="PERMANENTLY DELETE"
    targets ""
    ((${#TG[@]})) || { ST="Nothing to $mode here (already handled)"; SC=33; return; }
    for i in "${TG[@]}"; do ((tot += SZ[i])); done
    hsize "$tot"
    choose "$verb ${#TG[@]} item(s), $HS  -  [a]ll / [o]ne-by-one / [n]o" || { ST="Cancelled"; SC=33; return; }
    for i in "${TG[@]}"; do
        if [[ $CH == o ]]; then
            ltrunc "[${CT[i]}] ${OW[i]} ${HSZ[i]} ${PTH[i]}" $((COLUMNS - 20))
            ynq "$LT"; rc=$?
            ((rc == 2)) && break
            ((rc == 1)) && continue
        fi
        guard "$i" "$mode" || continue
        if remove_one "$i" "$mode"; then ((ok++)); unset 'MARK[$i]'; else ((fail++)); fi
    done
    build_view
    summary "${mode^}d" "$ok" "$fail"
    [[ $mode == quarantine ]] && ((ok)) && ST+=" (u restores)"
}

act_restore() {
    targets QUAR
    ((${#TG[@]})) || { ST="Nothing quarantined selected"; SC=33; return; }
    confirm "Restore ${#TG[@]} item(s) to original paths?" n || { ST="Cancelled"; SC=33; return; }
    local i p ok=0 fail=0
    for i in "${TG[@]}"; do
        p=${PTH[i]}
        if [[ -e $p || -L $p ]]; then LASTERR="original path exists: ${p##*/}"; log "FAIL restore $LASTERR"; ((fail++)); continue; fi
        if mkdir -p -- "${p%/*}" && mv -- "${QP[i]}" "$p" 2>/dev/null; then
            STT[i]=""; QP[i]=""; record restore "$i" -; ((ok++)); unset 'MARK[$i]'
        else
            LASTERR="mv failed"; log "FAIL restore $p"; ((fail++))
        fi
    done
    build_view; summary "Restored" "$ok" "$fail"
}

act_view() {
    ((${#VIEW[@]})) || return
    local i=${VIEW[CUR]} p t pat
    p=${PTH[i]}
    t=$(mktemp) || return
    pat=$SCRPAT; [[ ${CT[i]} == SENSTV ]] && pat=$SENPAT
    {
        printf 'Path : %s\nOwner: %s\nSize : %s\nWhy  : [%s] %s\nState: %s\n\n' "${p//[[:cntrl:]]/?}" "${OW[i]}" "${HSZ[i]}" "${CT[i]}" "${WH[i]}" "${STT[i]:-present}"
        [[ -n ${QP[i]} ]] && p=${QP[i]}
        stat -- "$p"
        command -v file >/dev/null && file -- "$p"
        echo
        if [[ -d $p ]]; then
            ls -la -- "$p" | head -50
        elif [[ ${CT[i]} == SCRIPT || ${CT[i]} == SENSTV ]]; then
            echo "--- matching lines (first 25) ---"
            grep -nIiE -m25 -e "$pat" -- "$p" | cut -c1-200
        elif grep -qI . -- "$p" 2>/dev/null; then
            echo "--- head ---"
            head -n 25 -- "$p" | cut -c1-200
        fi
    } >"$t" 2>&1
    pager "$t"; rm -f "$t"
}

act_report() {
    local dir def out
    if [[ -n $SUDO_USER && -d /home/$SUDO_USER/Desktop ]]; then dir=/home/$SUDO_USER/Desktop
    elif [[ -n $SUDO_USER && -d /home/$SUDO_USER ]]; then dir=/home/$SUDO_USER
    else dir=/root; fi
    def=$dir/pfinder-report-$(date +%Y%m%d-%H%M).md
    prompt "Report path:" 0 "$def" || { ST="Cancelled"; SC=33; return; }
    out=$PVAL; [[ -z $out ]] && return
    if [[ -e $out ]]; then confirm "$out exists. Overwrite?" n || { ST="Cancelled"; SC=33; return; }; fi
    if ! write_report >"$out" 2>/dev/null; then ST="Cannot write $out"; SC=31; return; fi
    [[ -n $SUDO_USER ]] && chown "$SUDO_USER" "$out" 2>/dev/null
    REPN=${#A_IDX[@]}
    log "report written: $out"
    ST="Report saved: $out"; SC=32
}

write_report() {
    local i k c n
    echo "# CyberPatriot Prohibited File Report"
    echo
    printf -- '- **Host:** %s\n- **Date:** %s\n- **Operator:** %s\n- **Scan roots:** %s\n' "$(hostname)" "$(date '+%F %T')" "${SUDO_USER:-root}" "${FR[*]:-${ROOTS[*]}}"
    printf -- '- **Hidden files in sensitive-text scan:** %s\n- **Quarantine folder:** `%s`\n- **Log:** `%s`\n\n' "$( ((HID)) && echo yes || echo no)" "$QDIR" "$LOGFILE"
    echo "## Summary"
    echo
    echo "| Category | Found | Deleted | Quarantined | Remaining |"
    echo "|---|---:|---:|---:|---:|"
    local freed=0
    for c in "${CATS[@]}"; do
        local f=0 d=0 q=0 r=0
        for i in "${!PTH[@]}"; do
            [[ ${CT[i]} == "$c" ]] || continue
            ((f++))
            case ${STT[i]} in DEL) ((d++, freed += SZ[i])) ;; QUAR) ((q++)) ;; *) ((r++)) ;; esac
        done
        echo "| $c | $f | $d | $q | $r |"
    done
    hsize "$freed"; echo; echo "Space freed by permanent deletion: **$HS**."
    echo
    echo "## Actions taken"
    echo
    if ((${#A_IDX[@]} == 0)); then echo "_None._"; else
        echo "| Time | Action | Category | Owner | Size | Path | SHA-256 |"
        echo "|---|---|---|---|---:|---|---|"
        for k in "${!A_IDX[@]}"; do
            i=${A_IDX[k]}; md "${PTH[i]}"
            echo "| ${A_TM[k]} | ${A_ACT[k]} | ${CT[i]} | ${OW[i]} | ${HSZ[i]} | \`$MD\` | ${A_SHA[k]:0:16} |"
        done
    fi
    echo
    echo "## Sensitive-text hits (keywords only, no contents)"
    echo
    n=0
    for i in "${!PTH[@]}"; do
        [[ ${CT[i]} == SENSTV ]] || continue
        ((n++ == 0)) && { echo "| Owner | Path | Keywords | State |"; echo "|---|---|---|---|"; }
        md "${PTH[i]}"; local p=$MD; md "${WH[i]#keyword: }"
        echo "| ${OW[i]} | \`$p\` | $MD | ${STT[i]:-present} |"
    done
    ((n)) || echo "_None._"
    echo
    echo "## Quarantined (not deleted)"
    echo
    n=0
    for i in "${!PTH[@]}"; do
        [[ ${STT[i]} == QUAR ]] || continue
        ((n++ == 0)) && { echo "| Original path | Now at |"; echo "|---|---|"; }
        md "${PTH[i]}"; local o=$MD; md "${QP[i]}"
        echo "| \`$o\` | \`$MD\` |"
    done
    ((n)) || echo "_None._"
    echo
    echo "Restore with \`u\` inside pfinder, or \`sudo mv <now-at> <original>\`. Delete the quarantine folder when finished."
    echo
    echo "## Remaining findings (reviewed, not removed)"
    echo
    n=0
    for i in "${!PTH[@]}"; do
        [[ -z ${STT[i]} && ${CT[i]} != SENSTV ]] || continue
        ((n++ == 0)) && { echo "| Category | Owner | Size | Path | Why |"; echo "|---|---|---:|---|---|"; }
        md "${PTH[i]}"; local p2=$MD; md "${WH[i]}"
        echo "| ${CT[i]} | ${OW[i]} | ${HSZ[i]} | \`$p2\` | $MD |"
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
                        if [[ -n ${MARK[$k]} ]]; then unset 'MARK[$k]'; else MARK[$k]=1; fi
                        ((CUR < n - 1)) && ((CUR++))
                    fi ;;
            a)      for k in "${VIEW[@]}"; do MARK[$k]=1; done ;;
            A)      MARK=() ;;
            ENTER|v) act_view ;;
            x)      act_remove quarantine ;;
            D|DEL)  act_remove delete ;;
            u)      act_restore ;;
            [0-5])  if [[ $KEY == 0 ]]; then CATF=""; else CATF=${CATS[KEY - 1]}; fi
                    build_view; ST="Category: ${CATF:-all}"; SC=36 ;;
            '/')    if prompt "Filter path:" 0 "$FILTER"; then FILTER=$PVAL; build_view; fi ;;
            s)      act_scan ;;
            '+')    if prompt "Add scan root:" 0; then
                        if [[ -d $PVAL ]]; then ROOTS+=("$PVAL"); ST="Added $PVAL (press s to scan)"; SC=36
                        else ST="Not a directory: $PVAL"; SC=31; fi
                    fi ;;
            h)      HID=$((1 - HID)); act_scan
                    [[ -z $ST || $SC == 36 ]] && ST+=" (hidden files in text scan: $( ((HID)) && echo on || echo off))" ;;
            L)      pager +G "$LOGFILE" ;;
            R)      act_report ;;
            '?')    show_help ;;
            ESC)    if [[ -n $FILTER ]]; then FILTER=""; build_view; fi ;;
            q|Q)    if ((${#A_IDX[@]} > REPN)); then
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
log "session start (invoked by ${SUDO_USER:-root})"
act_scan
main_loop
log "session end"
