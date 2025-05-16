#!/bin/bash

# U-72 (하) 및 U-43 (상) 점검 스크립트

# 로그 파일 경로 정의
LOG_FILE="/etc/rsyslog.conf"
LOG_FILES=("/var/log/secure" "/var/log/messages" "/var/log/cron" "/var/log/auth.log")
REPORT_FILE="/tmp/read.txt"  # 리포트를 저장할 파일

# 초기화
U_72_STATUS="양호"  # U-72 점검 상태
U_43_STATUS="양호"  # U-43 점검 상태

echo "[U-72] 로그 관리 정책 점검 시작" > $REPORT_FILE

# 1. U-72 (하) 점검: 로그 관리 정책 점검

# rsyslog.conf 파일이 존재하는지 확인
if [ -f $LOG_FILE ]; then
    echo "[U-72] rsyslog.conf 파일이 존재합니다." >> $REPORT_FILE
    # 중요한 로그 정책 점검: 로그 정책이 설정되어 있는지 확인
    grep -E ".*\.info;mail.none;authpriv.none;cron.none /var/log/messages" $LOG_FILE > /dev/null
    if [ $? -eq 0 ]; then
        echo "[U-72] /var/log/messages 로그 정책이 설정되어 있습니다. (양호)" >> $REPORT_FILE
    else
        echo "[U-72] /var/log/messages 로그 정책 설정이 없습니다. (취약)" >> $REPORT_FILE
        U_72_STATUS="취약"
    fi

    # /var/log/secure 파일 점검
    grep -E "authpriv.* /var/log/secure" $LOG_FILE > /dev/null
    if [ $? -eq 0 ]; then
        echo "[U-72] /var/log/secure 로그 정책이 설정되어 있습니다. (양호)" >> $REPORT_FILE
    else
        echo "[U-72] /var/log/secure 로그 정책 설정이 없습니다. (취약)" >> $REPORT_FILE
        U_72_STATUS="취약"
    fi
else
    echo "[U-72] rsyslog.conf 파일이 존재하지 않습니다. (취약)" >> $REPORT_FILE
    U_72_STATUS="취약"
fi

# 2. U-43 (상) 점검: 로그의 정기적 검토 및 보고

echo "[U-43] 로그 정기적 검토 및 보고 시작" >> $REPORT_FILE

# 로그 분석 결과 저장을 위한 파일 초기화
echo "로그 분석 리포트" >> $REPORT_FILE
echo "----------------------------" >> $REPORT_FILE
echo "분석 시각: $(date)" >> $REPORT_FILE
echo "----------------------------" >> $REPORT_FILE

# 각 로그 파일 점검: 로그인 실패 시도, 권한 상승 시도, FTP 접근 시도 등
LOG_ANALYZED=true
for LOG_FILE in "${LOG_FILES[@]}"; do
    if [ -f $LOG_FILE ]; then
        echo "[로그 파일] $LOG_FILE" >> $REPORT_FILE
        echo "최근 10줄 로그: " >> $REPORT_FILE
        tail -n 10 $LOG_FILE >> $REPORT_FILE
        echo "" >> $REPORT_FILE
    else
        echo "$LOG_FILE 파일이 존재하지 않습니다. (취약)" >> $REPORT_FILE
        LOG_ANALYZED=false
        U_43_STATUS="취약"
    fi
done

# U-43 점검 결과
if [ "$LOG_ANALYZED" = true ]; then
    echo "[U-43] 로그 파일 검토가 정상적으로 수행되었습니다. (양호)" >> $REPORT_FILE
else
    echo "[U-43] 로그 파일 중 일부가 존재하지 않거나 접근 불가합니다. (취약)" >> $REPORT_FILE
fi

# 최종 진단 결과 출력
echo "-------------------------------------------" >> $REPORT_FILE
echo "최종 진단 결과" >> $REPORT_FILE
echo "[U-72] 시스템 로깅 설정 점검 결과: $U_72_STATUS" >> $REPORT_FILE
echo "[U-43] 로그 정기적 검토 및 보고 결과: $U_43_STATUS" >> $REPORT_FILE
echo "-------------------------------------------" >> $REPORT_FILE

echo "리포트 파일이 생성되었습니다: $REPORT_FILE"
