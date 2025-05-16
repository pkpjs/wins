#!/bin/bash

# U-72 (하) 및 U-43 (상) 점검 스크립트

REPORT_FILE="/tmp/read.txt"  # 리포트를 저장할 파일
RSYSLOG_CONF="/etc/rsyslog.conf"
LOG_FILES=("/var/log/secure" "/var/log/messages" "/var/log/cron" "/var/log/auth.log")

# 초기화
U_72_STATUS="양호"  # U-72 점검 상태
U_43_STATUS="양호"  # U-43 점검 상태

echo "[U-43] 로그 정기적 검토 및 보고 시작" > "$REPORT_FILE"
echo "분석 시각: $(date)" >> "$REPORT_FILE"
echo "----------------------------" >> "$REPORT_FILE"

# 1. U-43 점검: 로그 파일 존재 및 최근 로그 일부 확인
LOG_ANALYZED=true
for log_file in "${LOG_FILES[@]}"; do
    if [ -f "$log_file" ]; then
        echo "[로그 파일] $log_file 존재 확인 (양호)" >> "$REPORT_FILE"
        echo "최근 10줄 로그:" >> "$REPORT_FILE"
        tail -n 10 "$log_file" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    else
        echo "[U-43] $log_file 파일이 존재하지 않습니다. (취약)" >> "$REPORT_FILE"
        LOG_ANALYZED=false
        U_43_STATUS="취약"
    fi
done

if [ "$LOG_ANALYZED" = true ]; then
    echo "[U-43] 로그 파일 검토가 정상적으로 수행되었습니다. (양호)" >> "$REPORT_FILE"
else
    echo "[U-43] 로그 파일 중 일부가 존재하지 않거나 접근 불가합니다. (취약)" >> "$REPORT_FILE"
fi

echo "" >> "$REPORT_FILE"
echo "[U-72] 로그 관리 정책 점검 시작" >> "$REPORT_FILE"

# 2. U-72 점검: rsyslog.conf 파일 존재 및 주요 로그 설정 점검
if [ -f "$RSYSLOG_CONF" ]; then
    echo "[U-72] $RSYSLOG_CONF 파일이 존재합니다." >> "$REPORT_FILE"

    grep -E "^\s*.*\.info;mail.none;authpriv.none;cron.none\s+/var/log/messages" "$RSYSLOG_CONF" > /dev/null
    if [ $? -eq 0 ]; then
        echo "[U-72] /var/log/messages 로그 정책이 설정되어 있습니다. (양호)" >> "$REPORT_FILE"
    else
        echo "[U-72] /var/log/messages 로그 정책 설정이 없습니다. (취약)" >> "$REPORT_FILE"
        U_72_STATUS="취약"
    fi

    grep -E "^\s*authpriv\.\*\s+/var/log/secure" "$RSYSLOG_CONF" > /dev/null
    if [ $? -eq 0 ]; then
        echo "[U-72] /var/log/secure 로그 정책이 설정되어 있습니다. (양호)" >> "$REPORT_FILE"
    else
        echo "[U-72] /var/log/secure 로그 정책 설정이 없습니다. (취약)" >> "$REPORT_FILE"
        U_72_STATUS="취약"
    fi

    grep -E "^\s*mail\.\*\s+/var/log/maillog" "$RSYSLOG_CONF" > /dev/null
    if [ $? -eq 0 ]; then
        echo "[U-72] /var/log/maillog 로그 정책이 설정되어 있습니다. (양호)" >> "$REPORT_FILE"
    else
        echo "[U-72] /var/log/maillog 로그 정책 설정이 없습니다. (취약)" >> "$REPORT_FILE"
        U_72_STATUS="취약"
    fi

    grep -E "^\s*cron\.\*\s+/var/log/cron" "$RSYSLOG_CONF" > /dev/null
    if [ $? -eq 0 ]; then
        echo "[U-72] /var/log/cron 로그 정책이 설정되어 있습니다. (양호)" >> "$REPORT_FILE"
    else
        echo "[U-72] /var/log/cron 로그 정책 설정이 없습니다. (취약)" >> "$REPORT_FILE"
        U_72_STATUS="취약"
    fi

    grep -E "^\s*\*\.alert\s+/dev/console" "$RSYSLOG_CONF" > /dev/null
    if [ $? -eq 0 ]; then
        echo "[U-72] *.alert /dev/console 설정이 되어 있습니다. (양호)" >> "$REPORT_FILE"
    else
        echo "[U-72] *.alert /dev/console 설정이 없습니다. (취약)" >> "$REPORT_FILE"
        U_72_STATUS="취약"
    fi

    grep -E "^\s*\*\.emerg\s+\*" "$RSYSLOG_CONF" > /dev/null
    if [ $? -eq 0 ]; then
        echo "[U-72] *.emerg * 설정이 되어 있습니다. (양호)" >> "$REPORT_FILE"
    else
        echo "[U-72] *.emerg * 설정이 없습니다. (취약)" >> "$REPORT_FILE"
        U_72_STATUS="취약"
    fi

else
    echo "[U-72] $RSYSLOG_CONF 파일이 존재하지 않습니다. (취약)" >> "$REPORT_FILE"
    U_72_STATUS="취약"
fi

# 최종 결과 요약
echo "-------------------------------------------" >> "$REPORT_FILE"
echo "최종 진단 결과" >> "$REPORT_FILE"
echo "[U-43] 로그 정기적 검토 및 보고 결과: $U_43_STATUS" >> "$REPORT_FILE"
echo "[U-72] 시스템 로깅 설정 점검 결과: $U_72_STATUS" >> "$REPORT_FILE"
echo "-------------------------------------------" >> "$REPORT_FILE"

echo "리포트가 생성되었습니다: $REPORT_FILE"

