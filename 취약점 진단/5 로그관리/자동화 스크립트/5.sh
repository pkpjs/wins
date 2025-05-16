#!/bin/bash

REPORT_FILE="/tmp/read.txt"  # 리포트를 저장할 파일
RSYSLOG_CONF="/etc/rsyslog.conf"  # 로그 설정 파일 경로
WHEEL_GROUP_USERS=$(getent group wheel | cut -d: -f4)  # wheel 그룹 사용자 리스트

# 초기화
U_43_STATUS="양호"  # U-43 점검 상태
U_72_STATUS="양호"  # U-72 점검 상태

# [U-43] 로그 정기적 검토 및 보고

echo "[U-43] 로그 정기적 검토 및 보고 시작" > $REPORT_FILE
echo "로그 분석 리포트" >> $REPORT_FILE
echo "----------------------------" >> $REPORT_FILE
echo "분석 시각: $(date)" >> $REPORT_FILE
echo "----------------------------" >> $REPORT_FILE

# Step 1: 로그 검토 및 분석 주기 수립

echo "[로그 파일] utmp, wtmp, btmp 파일 점검" >> $REPORT_FILE

if [ -f /var/log/utmp ]; then
    echo "[utmp] 마지막 로그인 정보:" >> $REPORT_FILE
    last -f /var/log/utmp | head -n 10 >> $REPORT_FILE
else
    echo "/var/log/utmp 파일이 존재하지 않습니다. (취약)" >> $REPORT_FILE
    U_43_STATUS="취약"
fi

if [ -f /var/log/wtmp ]; then
    echo "[wtmp] 로그인 기록:" >> $REPORT_FILE
    last -f /var/log/wtmp | head -n 10 >> $REPORT_FILE
else
    echo "/var/log/wtmp 파일이 존재하지 않습니다. (취약)" >> $REPORT_FILE
    U_43_STATUS="취약"
fi

if [ -f /var/log/btmp ]; then
    echo "[btmp] 로그인 실패 기록:" >> $REPORT_FILE
    lastb | head -n 10 >> $REPORT_FILE
else
    echo "/var/log/btmp 파일이 존재하지 않습니다. (취약)" >> $REPORT_FILE
    U_43_STATUS="취약"
fi

echo "[로그 파일] secure 파일 점검" >> $REPORT_FILE
echo "[secure] su 명령어 로그:" >> $REPORT_FILE

if [ -f /var/log/secure ]; then
    # su 명령어 로그에서 'su'와 관련된 모든 로그를 확인
    grep "su:" /var/log/secure | while read line; do
        # 실패한 인증 로그
        if [[ "$line" =~ "authentication failure" ]]; then
            echo "[su 명령어] 권한 상승 시도 있음: 실패한 인증" >> $REPORT_FILE
            echo "$line" >> $REPORT_FILE
            U_43_STATUS="취약"
        fi

        # 권한 상승 시도 후 세션 열린 로그
        if [[ "$line" =~ "session opened" ]]; then
            echo "[su 명령어] 권한 상승 시도 있음: 세션 열린 로그" >> $REPORT_FILE
            echo "$line" >> $REPORT_FILE
            U_43_STATUS="취약"
        fi
    done

    # wheel 그룹 사용자가 su 명령어 로그에서 권한 상승 시도한 경우 추가 점검
    echo "[로그 파일] su 명령어 권한 상승 시도 및 wheel 그룹 사용자 점검" >> $REPORT_FILE
    for user in $WHEEL_GROUP_USERS; do
        grep "su:" /var/log/secure | grep "$user" | while read line; do
            if [[ "$line" =~ "authentication failure" ]]; then
                echo "[su 명령어] 허용되지 않은 사용자($user)가 권한 상승 시도함." >> $REPORT_FILE
                echo "$line" >> $REPORT_FILE
                U_43_STATUS="취약"
            fi

            if [[ "$line" =~ "session opened" ]]; then
                echo "[su 명령어] 허용되지 않은 사용자($user)가 세션을 열었음." >> $REPORT_FILE
                echo "$line" >> $REPORT_FILE
                U_43_STATUS="취약"
            fi
        done
    done
else
    echo "/var/log/secure 파일이 존재하지 않습니다. (취약)" >> $REPORT_FILE
    U_43_STATUS="취약"
fi

# [U-72] 시스템 로깅 설정 점검

echo "[U-72] 시스템 로깅 설정 점검 시작" >> "$REPORT_FILE"

if [ -f "$RSYSLOG_CONF" ]; then
    echo "[U-72] $RSYSLOG_CONF 파일이 존재합니다." >> "$REPORT_FILE"

    grep -E "^\s*.*\.info;mail.none;authpriv.none;cron.none\s+/var/log/messages" "$RSYSLOG_CONF" > /dev/null
    [ $? -eq 0 ] && echo "[U-72] /var/log/messages 로그 정책이 설정되어 있습니다. (양호)" >> "$REPORT_FILE" || {
        echo "[U-72] /var/log/messages 로그 정책 설정이 없습니다. (취약)" >> "$REPORT_FILE"
        U_72_STATUS="취약"
    }

    grep -E "^\s*authpriv\.\*\s+/var/log/secure" "$RSYSLOG_CONF" > /dev/null
    [ $? -eq 0 ] && echo "[U-72] /var/log/secure 로그 정책이 설정되어 있습니다. (양호)" >> "$REPORT_FILE" || {
        echo "[U-72] /var/log/secure 로그 정책 설정이 없습니다. (취약)" >> "$REPORT_FILE"
        U_72_STATUS="취약"
    }

    grep -E "^\s*mail\.\*\s+/var/log/maillog" "$RSYSLOG_CONF" > /dev/null
    [ $? -eq 0 ] && echo "[U-72] /var/log/maillog 로그 정책이 설정되어 있습니다. (양호)" >> "$REPORT_FILE" || {
        echo "[U-72] /var/log/maillog 로그 정책 설정이 없습니다. (취약)" >> "$REPORT_FILE"
        U_72_STATUS="취약"
    }

    grep -E "^\s*cron\.\*\s+/var/log/cron" "$RSYSLOG_CONF" > /dev/null
    [ $? -eq 0 ] && echo "[U-72] /var/log/cron 로그 정책이 설정되어 있습니다. (양호)" >> "$REPORT_FILE" || {
        echo "[U-72] /var/log/cron 로그 정책 설정이 없습니다. (취약)" >> "$REPORT_FILE"
        U_72_STATUS="취약"
    }

    grep -E "^\s*\*\.alert\s+/dev/console" "$RSYSLOG_CONF" > /dev/null
    [ $? -eq 0 ] && echo "[U-72] *.alert /dev/console 설정이 되어 있습니다. (양호)" >> "$REPORT_FILE" || {
        echo "[U-72] *.alert /dev/console 설정이 없습니다. (취약)" >> "$REPORT_FILE"
        U_72_STATUS="취약"
    }

    grep -E "^\s*\*\.emerg\s+\*" "$RSYSLOG_CONF" > /dev/null
    [ $? -eq 0 ] && echo "[U-72] *.emerg * 설정이 되어 있습니다. (양호)" >> "$REPORT_FILE" || {
        echo "[U-72] *.emerg * 설정이 없습니다. (취약)" >> "$REPORT_FILE"
        U_72_STATUS="취약"
    }

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
