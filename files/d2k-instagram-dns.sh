#!/bin/sh
# Resolve Instagram/fbcdn/WhatsApp Web A records through d2k's own C resolver
# on the VPS (d2k-enroll POST /resolve) and manage only the exact static DNS
# pairs owned by this D2K installation.
set -eu
# A stop request (service stop, uninstall) takes effect only after the
# current command: an in-flight ndmc add finishes and stays owned, and no
# further change follows.
trap 'exit 143' TERM INT HUP
export PATH="${D2K_STUB_PATH:+$D2K_STUB_PATH:}/opt/sbin:/opt/bin:/sbin:/usr/sbin:/bin:/usr/bin"
DIR=${D2K_DIR:-/opt/d2k}
TGBIN=${D2K_RELEASE_ROOT:+$D2K_RELEASE_ROOT/d2ktg}
TGBIN=${TGBIN:-d2ktg}
META_RANGES=${D2K_META_RANGES:-$DIR/files/meta-ranges.txt}
MANIFEST=${D2K_INSTAGRAM_MANIFEST:-$DIR/state/instagram-ip-hosts.tsv}
LOG=${D2K_INSTAGRAM_LOG:-$DIR/log/instagram-dns.log}
RELAY_URL=${D2K_RELAY_URL:-https://85.192.60.175.nip.io:9443/resolve}
# The only list: d2ktg --check-instagram-ip and the VPS allowlist carry the
# same names (scripts/test-instagram-dns.sh compares them).
HOSTS='instagram.com www.instagram.com graph.instagram.com api.instagram.com i.instagram.com instagram.c10r.instagram.com static.cdninstagram.com scontent.cdninstagram.com static.xx.fbcdn.net scontent.xx.fbcdn.net web.whatsapp.com www.whatsapp.com scontent.whatsapp.net graph.whatsapp.com v.whatsapp.com static.whatsapp.net mmg.whatsapp.net pps.whatsapp.net'
mkdir -p "$(dirname "$LOG")" "$(dirname "$MANIFEST")" 2>/dev/null || true
log() { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" >>"$LOG"; }
mark_refresh_success() {
    state=${D2K_INSTAGRAM_SCHED_STATE:-$DIR/state/instagram-dns-last-success}
    tmp="$state.new.$$"
    # Date for the scheduler, time for the installer (an upgrade keeps a mark
    # younger than a day instead of refreshing the whole fleet at once).
    if printf '%s\n%s\n' "$(date +%Y-%m-%d)" "$(date +%s)" > "$tmp" && mv -f "$tmp" "$state"; then
        :
    else
        rm -f "$tmp"
        log 'не удалось записать дату успешного обновления; планировщик может повторить его сегодня'
    fi
}
managed_host() { case " $HOSTS " in *" $1 "*) return 0;; *) return 1;; esac; }
valid_ipv4() {
    case "$1" in *[!0-9.]*|*..*|.*|*.) return 1;; esac
    awk -F. 'NF==4 {for(i=1;i<=4;i++) if($i !~ /^[0-9]+$/ || $i>255) exit 1; exit 0} {exit 1}' <<EOF_IP
$1
EOF_IP
}
is_meta_ip() {
    valid_ipv4 "$1" || return 1
    awk -v ip="$1" 'function n(s,a){split(s,a,".");return ((a[1]*256+a[2])*256+a[3])*256+a[4]} BEGIN{v=n(ip);ok=0} /^[[:space:]]*#/||/^[[:space:]]*$/ {next} {split($0,p,"/");if(p[2]!~/^[0-9]+$/||p[2]<0||p[2]>32)next;s=2^(32-p[2]);if(int(v/s)==int(n(p[1])/s))ok=1} END{exit !ok}' "$META_RANGES" 2>/dev/null
}
# A live NDM configuration is never empty; empty output is a failed read and
# must not be taken as "none of our pins exist".
# Names whose edges may serve each other. A borrowed address is still
# verified for the borrowing name itself; families never mix.
meta_family() {
    case "$1" in
        instagram.com|*.instagram.com|*.cdninstagram.com) echo instagram ;;
        *.fbcdn.net) echo fbcdn ;;
        *.whatsapp.net|*.whatsapp.com) echo whatsapp ;;
    esac
}
# 0 when the address is a reachable Meta edge whose certificate is valid for
# host. DNS pinning checks edge reachability, not whether the SNI is already
# unblocked: the C control uses a neutral wire SNI and no HTTP traffic.
edge_verified() {
    probe_attempt=1
    probe_attempts=${D2K_IP_PROBE_ATTEMPTS:-2}
    while [ "$probe_attempt" -le "$probe_attempts" ]; do
        "$TGBIN" --check-instagram-ip "$1" "$2" "$ca_bundle" </dev/null >>"$LOG" 2>&1 && return 0
        if [ "$probe_attempt" -lt "$probe_attempts" ]; then
            log "повтор TLS-пробы $probe_attempt/$probe_attempts: $1 $2"
            sleep "${D2K_IP_PROBE_RETRY_DELAY:-1}"
        fi
        probe_attempt=$((probe_attempt + 1))
    done
    return 1
}
running_config() {
    _cfg=$(LD_LIBRARY_PATH='' ndmc -c 'show running-config' 2>/dev/null) || return 1
    [ -n "$_cfg" ] || return 1
    printf '%s\n' "$_cfg"
}
# One configuration dump per refresh, read again only after a change of ours.
ndm_cfg=
ndm_cfg_ok=0
ndm_changed=0
ndm_config() {
    [ "$ndm_cfg_ok" = 1 ] && return 0
    ndm_cfg=$(running_config) || return 1
    ndm_cfg_ok=1
}
ndm_touched() { ndm_cfg_ok=0; ndm_changed=1; }
# Saving writes the router's flash: only after an add or a removal.
ndm_save_if_changed() {
    [ "$ndm_changed" = 1 ] || return 0
    LD_LIBRARY_PATH='' ndmc -c 'system configuration save' >/dev/null 2>&1
}
record_exists() {
    ndm_config || return 2
    printf '%s\n' "$ndm_cfg" | awk -v h="$1" -v ip="$2" \
        '$1=="ip"&&$2=="host"&&$3==h&&$4==ip {f=1} END{exit !f}'
}
# I3: every owned pin present in NDM is re-checked from the router itself,
# independently of the VPS. Sets dead_pins ("host ip" lines) and alive_pins.
dead_pins=
verified_pins=
alive_pins=0
recheck_owned() {
    [ -s "$MANIFEST" ] || return 0
    while read -r host ip _extra; do
        { [ -n "${host:-}" ] && [ -n "${ip:-}" ]; } || continue
        if ! managed_host "$host" || ! valid_ipv4 "$ip"; then continue; fi
        if record_exists "$host" "$ip"; then :; else
            [ "$?" = 1 ] && continue
            log 'не удалось прочитать NDM для проверки своих записей'; return 1
        fi
        if edge_verified "$host" "$ip"; then
            alive_pins=$((alive_pins + 1))
            verified_pins="${verified_pins}${host} ${ip}\n"
        else
            dead_pins="${dead_pins}${host} ${ip}
"
            log "своя запись не прошла локальную TLS-проверку: $host $ip"
        fi
    done < "$MANIFEST"
}
is_dead_pin() {
    case "
$dead_pins" in *"
$1 $2
"*) return 0;; esac
    return 1
}
# Removes the dead owned pins (only those) from NDM and from the manifest.
# The caller decides whether the checks can be trusted.
drop_dead_pins() {
    [ -n "$dead_pins" ] || return 0
    while read -r host ip; do
        { [ -n "${host:-}" ] && [ -n "${ip:-}" ]; } || continue
        if record_exists "$host" "$ip"; then
            LD_LIBRARY_PATH='' ndmc -c "no ip host $host $ip" >/dev/null 2>&1 || { log "ошибка удаления недоступной записи $host $ip"; return 1; }
            ndm_touched
            log "удалена недоступная D2K-запись $host $ip; имя снова решается обычным DNS"
        else
            [ "$?" = 1 ] || { log "не удалось проверить NDM перед удалением $host $ip"; return 1; }
        fi
    done <<EOF_DEAD
$dead_pins
EOF_DEAD
    kept="$MANIFEST.alive.$$"
    : > "$kept"
    while read -r host ip _extra; do
        { [ -n "${host:-}" ] && [ -n "${ip:-}" ]; } || continue
        is_dead_pin "$host" "$ip" && continue
        printf '%s %s\n' "$host" "$ip" >> "$kept"
    done < "$MANIFEST"
    mv -f "$kept" "$MANIFEST"
    dead_pins=
}
remove_owned() {
    [ -s "$MANIFEST" ] || { rm -f "$MANIFEST"; log 'нет D2K-owned DNS-записей Instagram/WhatsApp'; return 0; }
    command -v ndmc >/dev/null 2>&1 || { log 'ndmc отсутствует; manifest оставлен'; return 1; }
    while read -r host ip _extra; do
        { [ -n "${host:-}" ] && [ -n "${ip:-}" ]; } || continue
        if ! managed_host "$host" || ! valid_ipv4 "$ip"; then
            log 'игнорирую некорректную строку manifest'
            continue
        fi
        if record_exists "$host" "$ip"; then
            LD_LIBRARY_PATH='' ndmc -c "no ip host $host $ip" >/dev/null 2>&1 || { log "ошибка удаления $host $ip"; return 1; }
            ndm_touched
            log "удалена D2K-запись $host $ip"
        else
            rc=$?
            [ "$rc" = 1 ] || { log "не удалось проверить NDM перед удалением $host $ip"; return 1; }
        fi
    done < "$MANIFEST"
    if ! ndm_save_if_changed; then
        log 'не удалось сохранить конфигурацию NDM; manifest оставлен для повтора'
        return 1
    fi
    rm -f "$MANIFEST"
}
refresh() {
    if ! command -v ndmc >/dev/null 2>&1; then log 'ndmc отсутствует — пропускаю (не Keenetic)'; return 0; fi
    [ -s "$META_RANGES" ] || { log "нет списка диапазонов Meta: $META_RANGES"; return 1; }
    command -v "$TGBIN" >/dev/null 2>&1 || { log 'нет C-инструмента проверки адресов d2ktg'; return 1; }
    ca_bundle=${D2K_IP_CA_BUNDLE:-/opt/etc/ssl/certs/ca-certificates.crt}
    [ -r "$ca_bundle" ] || ca_bundle=/etc/ssl/certs/ca-certificates.crt
    [ -r "$ca_bundle" ] || { log 'нет системных доверенных CA; установите ca-bundle'; return 1; }
    # Owned pins are checked first, from here: if the VPS is gone, a pin to a
    # retired edge must still go away.
    recheck_owned || return 1
    # No credential: the VPS answers public DNS data for this fixed list only.
    RELAY_AUTHORITY=${RELAY_URL#*://}; RELAY_AUTHORITY=${RELAY_AUTHORITY%%/*}
    RELAY_HOST=${RELAY_AUTHORITY%%:*}
    RELAY_PORT=443
    case "$RELAY_AUTHORITY" in *:*) RELAY_PORT=${RELAY_AUTHORITY##*:};; esac
    RESOLVE_IP=
    case "$RELAY_HOST" in *.nip.io) _nip=${RELAY_HOST%.nip.io}; case "$_nip" in *[!0-9.]*|*..*|.*|*.) ;; *.*.*.*.*) ;; *.*.*.*) RESOLVE_IP=$_nip;; esac;; esac
    body='{"hosts":['; first=1
    for host in $HOSTS; do [ "$first" = 1 ] || body="$body,"; body="$body\"$host\""; first=0; done
    body="$body]}"
    attempts=${D2K_RESOLVE_ATTEMPTS:-3}
    attempt=1
    response=
    while [ "$attempt" -le "$attempts" ]; do
        if [ -n "$RESOLVE_IP" ]; then
            response=$(curl -fsS --connect-timeout "${D2K_RESOLVE_CONNECT_TIMEOUT:-5}" \
                --max-time "${D2K_RESOLVE_TIMEOUT:-15}" --resolve "$RELAY_HOST:$RELAY_PORT:$RESOLVE_IP" \
                -X POST "$RELAY_URL" -H 'Content-Type: application/json' \
                --data "$body" 2>>"$LOG") && break
        else
            response=$(curl -fsS --connect-timeout "${D2K_RESOLVE_CONNECT_TIMEOUT:-5}" \
                --max-time "${D2K_RESOLVE_TIMEOUT:-15}" -X POST "$RELAY_URL" \
                -H 'Content-Type: application/json' \
                --data "$body" 2>>"$LOG") && break
        fi
        log "VPS /resolve: попытка $attempt/$attempts не удалась"
        attempt=$((attempt + 1))
        [ "$attempt" -le "$attempts" ] && sleep "${D2K_RESOLVE_RETRY_DELAY:-3}"
    done
    if [ -z "$response" ]; then
        if [ -n "$dead_pins" ] && [ "$alive_pins" -gt 0 ]; then
            drop_dead_pins || return 1
            ndm_save_if_changed || log 'не удалось сохранить конфигурацию NDM'
            log 'VPS /resolve не ответил после повторов; недоступные свои записи сняты, остальные не изменены'
        elif [ -n "$dead_pins" ]; then
            log 'VPS /resolve не ответил, и ни одна своя запись не прошла проверку — похоже, нет связи у самого роутера; DNS-записи не изменены'
        else
            log 'VPS /resolve не ответил после повторов; текущие DNS-записи не изменены'
        fi
        return 1
    fi
    log "VPS /resolve ответил (попытка $attempt/$attempts)"
    printf '%s' "$response" | grep -q '"results"' || { log 'ответ VPS не содержит results'; return 1; }
    parsed=$(printf '%s' "$response" | sed -e 's/.*"results":{//' -e 's/}}$//' -e 's/\],/\n/g' -e 's/\]$//' | awk '{n1=index($0,"\"");if(!n1)next;r=substr($0,n1+1);n2=index(r,"\"");if(!n2)next;h=substr(r,1,n2-1);ips=substr(r,n2+1);gsub(/[^0-9.,]/,"",ips);n=split(ips,a,",");for(i=1;i<=n;i++)if(a[i]~/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/)print h" "a[i]}')
    [ -n "$parsed" ] || { log 'не удалось разобрать ответ VPS'; return 1; }
    filtered=
    missing=
    for host in $HOSTS; do
        tried=0
        kept=0
        rejected=0
        for ip in $(printf '%s\n' "$parsed" | awk -v h="$host" '$1==h && !seen[$2]++ {print $2}' | head -8); do
            if ! is_meta_ip "$ip"; then
                log "отброшен адрес вне диапазонов Meta: $host $ip"
                rejected=$((rejected + 1))
                continue
            fi
            [ "$tried" -lt 4 ] || break
            tried=$((tried + 1))
            if edge_verified "$host" "$ip"; then
                filtered="${filtered}${host} ${ip}\n"
                kept=$((kept + 1))
            else
                rejected=$((rejected + 1))
                log "адрес не прошёл TLS-проверку доступности и сертификата Meta: $host $ip"
            fi
        done
        if [ "$kept" -eq 0 ] && [ "$rejected" -eq 0 ]; then rejected=1; fi
        [ "$rejected" -eq 0 ] || missing="${missing}${host} ${rejected}\n"
    done
    # Freeze the direct results so a borrowed address cannot become a donor.
    direct=$filtered
    # Replace each rejected address with a distinct sibling address verified
    # again for the target name. Keep the existing limit on fallback probes.
    while read -r host rejected; do
        [ -n "$host" ] || continue
        family=$(meta_family "$host")
        [ -n "$family" ] || continue
        answered=" $(printf '%s\n' "$parsed" | awk -v h="$host" '$1==h{print $2}' | tr '\n' ' ') "
        candidates=$(printf '%b' "$direct$verified_pins" |
            while read -r sibling ip _extra; do
                { [ -n "${sibling:-}" ] && [ -n "${ip:-}" ]; } || continue
                [ "$sibling" != "$host" ] || continue
                if ! managed_host "$sibling" || ! valid_ipv4 "$ip"; then continue; fi
                is_dead_pin "$sibling" "$ip" && continue
                [ "$(meta_family "$sibling")" = "$family" ] || continue
                printf '%s %s\n' "$ip" "$sibling"
            done | awk '!seen[$1]++')
        tried=0
        while read -r ip sibling; do
            [ -n "${ip:-}" ] || continue
            case "$answered" in *" $ip "*) continue;; esac
            [ "$tried" -lt 4 ] || break
            tried=$((tried + 1))
            is_meta_ip "$ip" || { log "адрес семейства вне диапазонов Meta: $host $ip"; continue; }
            if edge_verified "$host" "$ip"; then
                filtered="${filtered}${host} ${ip}\n"
                rejected=$((rejected - 1))
                log "адрес семейства: $host $ip (от $sibling), сертификат проверен для $host"
                [ "$rejected" -gt 0 ] || break
            else
                log "адрес семейства не прошёл TLS-проверку для $host: $ip (от $sibling)"
            fi
        done <<EOF_CANDIDATES
$candidates
EOF_CANDIDATES
    done <<EOF_MISSING
$(printf '%b' "$missing")
EOF_MISSING
    # Each family stands on its own. The Instagram family is pinned only with
    # a verified instagram.com; WhatsApp and fbcdn never wait for it.
    if [ -n "$filtered" ] && ! printf '%b' "$filtered" | awk '$1=="instagram.com" {ok=1} END{exit !ok}'; then
        filtered=$(printf '%b' "$filtered" | while read -r host ip; do
            [ -n "${host:-}" ] || continue
            [ "$(meta_family "$host")" = instagram ] || printf '%s %s\\n' "$host" "$ip"
        done)
        log 'семейство instagram: нет проверенного адреса instagram.com; его записи не изменены, WhatsApp и fbcdn обновляются отдельно'
    fi
    if [ -z "$filtered" ]; then
        # Some check passed in this refresh: the uplink works, so the dead
        # pins really are dead.
        if [ -n "$dead_pins" ] && [ "$alive_pins" -gt 0 ]; then
            drop_dead_pins || return 1
            ndm_save_if_changed || log 'не удалось сохранить конфигурацию NDM'
        fi
        log 'VPS ответил, но нет адресов с доступным и подлинным TLS-сервисом Meta; остальные DNS-записи не изменены'
        return 1
    fi
    drop_dead_pins || return 1
    next="$MANIFEST.new.$$"; : > "$next"
    if [ -f "$MANIFEST" ]; then
        # Keep owning only pairs NDM actually has: a claim written by a refresh
        # that died before its add (or a pin the user deleted) is dropped, so
        # it can never cover the user's own later identical pin.
        ndm_config || { rm -f "$next"; log 'не удалось прочитать NDM перед обновлением'; return 1; }
        while read -r host ip _extra; do
            { [ -n "${host:-}" ] && [ -n "${ip:-}" ]; } || continue
            if ! managed_host "$host" || ! valid_ipv4 "$ip"; then continue; fi
            if printf '%s\n' "$ndm_cfg" | awk -v h="$host" -v ip="$ip" '$1=="ip"&&$2=="host"&&$3==h&&$4==ip {f=1} END{exit !f}'; then
                printf '%s %s\n' "$host" "$ip" >> "$next"
            else
                log "владение снято: записи $host $ip нет в NDM"
            fi
        done < "$MANIFEST"
    fi
    add_failed=0
    for host in $HOSTS; do
        for ip in $(printf '%b' "$filtered" | awk -v h="$host" '$1==h{print $2}' | sort -u); do
            # Existing records remain user-owned unless our manifest already claims them.
            if record_exists "$host" "$ip"; then
                continue
            else
                rc=$?
                [ "$rc" = 1 ] || { rm -f "$next"; log "не удалось проверить NDM перед добавлением $host $ip"; return 1; }
            fi
            # Claim the absent pair before adding it: a refresh stopped at any
            # point (service stop, uninstall) still leaves it removable, and
            # remove skips a claimed pair that NDM never received.
            printf '%s %s\n' "$host" "$ip" >> "$MANIFEST"
            if LD_LIBRARY_PATH='' ndmc -c "ip host $host $ip" >/dev/null 2>&1; then
                ndm_touched
                printf '%s %s\n' "$host" "$ip" >> "$next"; log "добавлена D2K-запись $host $ip"
            else ndm_touched; add_failed=1; log "ошибка добавления $host $ip"; fi
        done
    done
    if [ "$add_failed" = 1 ]; then
        # Remember any partial additions so uninstall still owns them, but
        # never retire previous pins when replacement failed.
        sort -u "$next" > "$MANIFEST"; rm -f "$next"
        ndm_save_if_changed || true
        log 'NDM не принял новые записи; прежние адреса сохранены, обновление не завершено'
        return 1
    fi
    # Replace stale pairs owned by D2K only after this host has at least one
    # freshly probed address installed. A failed/empty host probe keeps its
    # previous working pins; unrelated user-owned records are never touched.
    if [ -f "$MANIFEST" ]; then
        stale_removed=0
        while read -r host ip _extra; do
            { [ -n "${host:-}" ] && [ -n "${ip:-}" ]; } || continue
            if ! managed_host "$host"; then continue; fi
            if ! valid_ipv4 "$ip"; then continue; fi
            fresh=$(printf '%b' "$filtered" | awk -v h="$host" '$1==h{print $2}' | tr '\n' ' ')
            [ -n "$fresh" ] || continue
            case " $fresh " in *" $ip "*) continue;; esac
            if record_exists "$host" "$ip"; then
                if LD_LIBRARY_PATH='' ndmc -c "no ip host $host $ip" >/dev/null 2>&1; then
                    ndm_touched
                    log "удалена устаревшая D2K-запись $host $ip"
                    stale_removed=1
                else
                    rm -f "$next"; log "ошибка удаления устаревшей записи $host $ip"; return 1
                fi
            else
                rc=$?
                [ "$rc" = 1 ] || { rm -f "$next"; log "не удалось проверить NDM перед заменой $host $ip"; return 1; }
                stale_removed=1
            fi
        done < "$MANIFEST"
        if [ "$stale_removed" = 1 ]; then
            kept="$next.kept"
            : > "$kept"
            while read -r host ip _extra; do
                { [ -n "${host:-}" ] && [ -n "${ip:-}" ]; } || continue
                fresh=$(printf '%b' "$filtered" | awk -v h="$host" '$1==h{print $2}' | tr '\n' ' ')
                if [ -n "$fresh" ]; then case " $fresh " in *" $ip "*) :;; *) continue;; esac; fi
                printf '%s %s\n' "$host" "$ip" >> "$kept"
            done < "$next"
            mv -f "$kept" "$next"
        fi
    fi
    sort -u "$next" > "$next.sorted"; mv -f "$next.sorted" "$MANIFEST"; rm -f "$next"
    if ! ndm_save_if_changed; then
        log 'не удалось сохранить конфигурацию NDM'
        return 1
    fi
    log 'обновление DNS Instagram/WhatsApp завершено'
    mark_refresh_success
}
case "${1:-}" in refresh) refresh;; remove) remove_owned;; *) echo "usage: $0 refresh|remove" >&2; exit 2;; esac
