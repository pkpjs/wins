#!/bin/bash

# 출력 파일 지정
OUTPUT="read1.txt"

# 로그 설정 파일 확인
if [ -f /etc/rsyslog.conf ]; then
    LOGCONF="/etc/rsyslog.conf"
elif [ -f /etc/syslog.conf ]; then
    LOGCONF="/etc/syslog.conf"
else
    echo "[!] 로그 설정 파일을 찾을 수 없습니다." > "$OUTPUT"
    exit 1
fi

{
    echo "[+] 사용 중인 로그 설정 파일: $LOGCONF"

    # 점검할 항목 목록
    declare -A targets=(
        ["*.info;mail.none;authpriv.none;cron.none"]="messages"
        ["authpriv.*"]="secure"
        ["mail.*"]="maillog"
        ["cron.*"]="cron"
        ["*.alert"]="dev/console"
        ["*.emerg"]="*"
    )

    echo
    echo "[*] 로그 설정 점검 결과:"
    echo "-----------------------------------------"

    for pattern in "${!targets[@]}"; do
        grep -E "^\s*$pattern\s+" "$LOGCONF" > /dev/null
        if [ $? -eq 0 ]; then
            echo "[O] $pattern → /var/log/${targets[$pattern]} 설정 존재"
        else
            echo "[X] $pattern → /var/log/${targets[$pattern]} 설정 누락"
        fi
    done

    echo "-----------------------------------------"
} > "$OUTPUT"
