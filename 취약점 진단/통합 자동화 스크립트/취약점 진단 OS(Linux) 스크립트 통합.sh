#!/bin/bash

# 4조 ASCII 아트 배너
echo "==============================================="
echo "|                                              |"
echo "|     444   JJJJJ   OOOOO                      |"
echo "|    4  4     J    O     O                     |"
echo "|   4  44     J    O     O                     |"
echo "|  444444     J    O     O                     |"
echo "|      4    J J    O     O                     |"
echo "|      4    J J    O     O                     |"
echo "|   4444     J      OOOOO                      |"
echo "|                                              |"
echo "|         🔐  4조 보안 점검 스크립트 🔐        |"
echo "==============================================="
echo ""

#<--------------------------- 각 함수 출력 설정 값값 ---------------------->
LOG_DIR="./logs"
mkdir -p "$LOG_DIR"

# 로그 출력 함수
log_result() {
    local ITEM="$1"
    local STATUS="$2"
    local DETAILS="$3"
    echo "$ITEM | $STATUS | $DETAILS" >> "$LOG_DIR/${ITEM}.txt"
}

RSYSLOG_CONF="/etc/rsyslog.conf"
WHEEL_GROUP_USERS=$(getent group wheel | cut -d: -f4)


# <--------------------------- 계정 관리리 ---------------------->
# U-01: 원격 root 접속 제한
check_u01() {
    sshd_config="/etc/ssh/sshd_config"
    if [ -f $sshd_config ]; then
        if grep -qE "^PermitRootLogin\s+no" $sshd_config; then
            log_result "U-01" "Pass" "SSH root 접속 비활성화"
        else
            log_result "U-01" "Warn" "SSH root 접속 허용됨. /etc/ssh/sshd_config 수정 필요"
        fi
    else
        log_result "U-01" "Warn" "SSH 구성 파일 누락"
    fi
}

# U-02: 패스워드 복잡성 설정
check_u02() {
    pwquality_conf="/etc/security/pwquality.conf"
    if [ -f $pwquality_conf ]; then
        if grep -qE "minlen\s*=\s*8" $pwquality_conf && \
           grep -qE "dcredit\s*=\s*-1" $pwquality_conf && \
           grep -qE "ucredit\s*=\s*-1" $pwquality_conf && \
           grep -qE "lcredit\s*=\s*-1" $pwquality_conf && \
           grep -qE "ocredit\s*=\s*-1" $pwquality_conf; then
            log_result "U-02" "Pass" "패스워드 복잡성 요구사항 충족"
        else
            log_result "U-02" "Warn" "패스워드 복잡성 설정 부족"
        fi
    else
        log_result "U-02" "Warn" "pwquality.conf 파일 누락"
    fi
}

# U-03: 계정 잠금 임계값 설정
check_u03() {
    pam_faillock=$(grep "pam_faillock.so" /etc/pam.d/system-auth)
    if echo "$pam_faillock" | grep -q "deny=5"; then
        log_result "U-03" "Pass" "계정 잠금 임계값(5회) 설정됨"
    elif [ -n "$pam_faillock" ]; then
        log_result "U-03" "Warn" "pam_faillock.so는 있으나 deny=5 설정이 아님"
    else
        log_result "U-03" "Warn" "pam_faillock.so 설정 없음"
    fi
}

# U-04: 패스워드 파일 보호
check_u04() {
    if [ -f "/etc/shadow" ]; then
        shadow_perm=$(stat -c "%a" /etc/shadow)
        if [ "$shadow_perm" -le 400 ]; then
            log_result "U-04" "Pass" "shadow 파일 권한 적절"
        else
            log_result "U-04" "Warn" "shadow 파일 권한 취약 (현재: $shadow_perm)"
        fi
    else
        log_result "U-04" "Warn" "shadow 파일 없음"
    fi
}

# U-44: root UID 중복 확인
check_u44() {
    root_uid_count=$(awk -F: '$3==0 {print $1}' /etc/passwd | wc -l)
    if [ "$root_uid_count" -eq 1 ]; then
        log_result "U-44" "Pass" "root UID 중복 없음"
    else
        log_result "U-44" "Warn" "UID 0 중복 계정 존재"
    fi
}

# U-45: su 제한 설정
check_u45() {
    if grep -qE "^auth\s+required\s+pam_wheel.so" /etc/pam.d/su; then
        log_result "U-45" "Pass" "su 명령어 wheel 그룹 제한 설정됨"
    else
        log_result "U-45" "Warn" "su 제한 설정 미흡"
    fi
}

# U-46: 최소 패스워드 길이
check_u46() {
    if grep -qE "PASS_MIN_LEN\s+8" /etc/login.defs; then
        log_result "U-46" "Pass" "최소 패스워드 길이 8자 이상"
    else
        log_result "U-46" "Warn" "패스워드 최소 길이 미달"
    fi
}

# U-47: 패스워드 최대 사용 기간
check_u47() {
    max_days=$(grep "PASS_MAX_DAYS" /etc/login.defs | grep -v '#' | awk '{print $2}')
    if [ "$max_days" -le 90 ]; then
        log_result "U-47" "Pass" "패스워드 최대 사용 기간 적절(90일 이하)"
    else
        log_result "U-47" "Warn" "패스워드 최대 사용 기간 초과(현재: $max_days일)"
    fi
}

# U-48: 패스워드 최소 사용 기간
check_u48() {
    min_days=$(grep "PASS_MIN_DAYS" /etc/login.defs | grep -v '#' | awk '{print $2}')
    if [ "$min_days" -ge 1 ]; then
        log_result "U-48" "Pass" "패스워드 최소 사용 기간 적절(1일 이상)"
    else
        log_result "U-48" "Warn" "패스워드 재사용 제한 미흡"
    fi
}

# U-49: 불필요 계정 제거
check_u49() {
    WARN_FLAG=0
    UID_MIN=$(grep "^UID_MIN" /etc/login.defs | awk '{print $2}')
    [ -z "$UID_MIN" ] && UID_MIN=1000  # 기본 UID_MIN 설정

    # 결과 저장용 배열
    report_entries=()

    # 일반 사용자 계정 검사
    never_logged=()
    long_unaccessed=()
    while read -r user; do
        user_shell=$(getent passwd "$user" | cut -d: -f7)
        [[ "$user_shell" == *"nologin"* ]] && continue

        last_login=$(LANG=C lastlog -u "$user" 2>/dev/null | tail -1)
        
        if [[ "$last_login" == *"Never logged in"* ]]; then
            never_logged+=("$user")
        else
            login_date=$(echo "$last_login" | awk '{print $5,$6,$7,$8}')
            login_epoch=$(date -d "$login_date" +%s 2>/dev/null)
            current_epoch=$(date +%s)
            days_since_login=$(( (current_epoch - login_epoch) / 86400 ))

            if [ "$days_since_login" -ge 90 ]; then
                long_unaccessed+=("$user (${days_since_login}일)")
            fi
        fi
    done < <(getent passwd | awk -F: -v min="$UID_MIN" '$3 >= min {print $1}')

    # 결과 포맷팅
    [ ${#never_logged[@]} -gt 0 ] && report_entries+=("미사용 계정: $(IFS=,; echo "${never_logged[*]}") (로그인 기록 없음)")
    [ ${#long_unaccessed[@]} -gt 0 ] && report_entries+=("장기 미접속 계정: $(IFS=,; echo "${long_unaccessed[*]}")")
    
    # 시스템 계정 검사
    system_accs=()
    for acc in "lp" "uucp" "games"; do
        getent passwd "$acc" &>/dev/null && system_accs+=("$acc")
    done
    [ ${#system_accs[@]} -gt 0 ] && report_entries+=("불필요 시스템 계정 존재: $(IFS=,; echo "${system_accs[*]}")")

    # 최종 보고
    if [ ${#report_entries[@]} -gt 0 ]; then
        log_result "U-49" "Warn" "${report_entries[*]// / }"  # 공백 제거
        WARN_FLAG=1
    else
        log_result "U-49" "Pass" "모든 계정이 정상 관리되고 있습니다."
    fi
}

# U-50: root 그룹 유일성
check_u50() {
    root_group_count=$(grep "^root:" /etc/group | cut -d: -f4 | tr ',' '\n' | wc -w)
    if [ "$root_group_count" -eq 0 ]; then
        log_result "U-50" "Pass" "root 그룹 관리자만 포함"
    else
        log_result "U-50" "Warn" "root 그룹에 불필요 사용자 포함"
    fi
}

# U-51: 비활성 계정 검사 
check_u51() {
    empty_groups=""
    GID_THRESHOLD=1000  # 시스템 그룹과 사용자 그룹 분기점

    while IFS=: read -r group_name _ gid members; do
        # 시스템 그룹(GID < 1000)은 제외
        if [ -z "$members" ] && [ "$gid" -ge $GID_THRESHOLD ]; then
            empty_groups+="$group_name(GID:$gid), "
        fi
    done < /etc/group

    if [ -n "$empty_groups" ]; then
        log_result "U-51" "Warn" "일반 사용자 그룹 중 구성원 없음: ${empty_groups%, }"
    else
        log_result "U-51" "Pass" "사용자 생성 그룹에 구성원 존재"
    fi
}

# U-52: UID 중복 검사
check_u52() {
    duplicate_uids=$(cut -d: -f3 /etc/passwd | sort | uniq -d)
    if [ -z "$duplicate_uids" ]; then
        log_result "U-52" "Pass" "중복 UID 없음"
    else
        log_result "U-52" "Warn" "중복 UID 존재: $duplicate_uids"
    fi
}

# U-53: 시스템 계정 쉘 제한
check_u53() {
    invalid_shells=("/bin/sh" "/bin/bash" "/bin/csh" "/bin/ksh")
    for user in $(awk -F: '$3 < 1000 {print $1}' /etc/passwd); do
        shell=$(grep "^$user:" /etc/passwd | cut -d: -f7)
        if [[ " ${invalid_shells[@]} " =~ " ${shell} " ]]; then
            log_result "U-53" "Warn" "시스템 계정 $user 쉘 활성화: $shell"
            return
        fi
    done
    log_result "U-53" "Pass" "시스템 계정 쉘 제한 적절"
}

# U-54: 세션 타임아웃 설정
check_u54() {
    if grep -qE "TMOUT=600" /etc/profile /etc/bashrc; then
        log_result "U-54" "Pass" "세션 타임아웃 10분 설정"
    else
        log_result "U-54" "Warn" "세션 타임아웃 미설정"
    fi
}

# <--------------------------- 파일 및 디렉터리 관리리 ---------------------->

# U-05: root 홈, 패스 디렉터리 권한 및 패스 설정
check_u05() {
  LOG_FILE="$LOG_DIR/U-05.txt"

  {
    echo "=================================================================="
    echo "  취악점 코드        : [U-05]"
    echo "  진단 항목          : root PATH 및 홈 권한 설정"
    echo "  위험도             : 상"
    echo "------------------------------------------------------------------"
    echo "  [점검 결과]"

    result="양호"
    home_result="양호"
    final_result="양호"

    path_files=("/root/.bash_profile" "/etc/profile" "/root/.profile" "/root/.cshrc")
    path_file_found="false"
    for pf in "${path_files[@]}"; do
      if [ -f "$pf" ]; then
        path_file_found="true"
        break
      fi
    done

    current_path=$(echo "$PATH")

    if [[ "$current_path" == .* || "$current_path" == *:.:* || "$current_path" == *::* ]]; then
      result="취악"
      echo "  - PATH 상태         : 취악"
      echo "    설정 내용         : $current_path"
    elif [[ "$path_file_found" == "false" ]]; then
      result="취악"
      echo "  - PATH 상태         : 취악"
      echo "    설정 내용         : PATH 설정 파일 없음 (${path_files[*]})"
    else
      echo "  - PATH 상태         : 양호"
      echo "    설정 내용         : $current_path"
    fi

    if [ ! -d "/root" ]; then
      home_result="취악"
      echo "  - /root 상태         : 디렉터리 없음 (취악)"
    fi

    [[ "$result" == "취악" || "$home_result" == "취악" ]] && final_result="취악"

    echo "------------------------------------------------------------------"
    echo "  최종 진단 결과     : $final_result"
    echo "=================================================================="

    if [[ "$final_result" == "취악" ]]; then
      echo ""
      echo "[취악 사유 상세 설명]"
      if [[ "$result" == "취악" ]]; then
        if [[ "$path_file_found" == "false" ]]; then
          echo "- root 계정의 환경변수 설정파일과 /etc/profile 등이 존재하지 않아 보안 설정 확인이 불가능합니다."
        else
          echo "- PATH 환경변수에 현재 디렉터리('.') 또는 '::'가 포함되어 있어, 악성 실행파일이 먼저 실행될 위험이 존재합니다."
        fi
      fi
      if [[ "$home_result" == "취악" ]]; then
        echo "- /root 디렉터리가 존재하지 않아 root 계정의 보안 설정이 뛰려진 가능성이 있습니다."
      fi
      echo ""
      echo "[조치 권고 사항]"
      if [[ "$result" == "취악" ]]; then
        echo "- root 계정의 환경변수 설정파일(\"/root/.bash_profile\", \"/root/.profile\", \"/root/.cshrc\" 등)과"
        echo "  \"/etc/profile\"에서 PATH 환경변수에 포함된 현재 디렉터리 '.' 또는 '::'는 ë \xeb8f8c추에 위치하도록 수정하세요."
        echo "- 예시: export PATH=\$PATH:. (→ 안전하지 않음)"
        echo "       export PATH=/usr/local/bin:/usr/bin:/bin:. (→ 마지막에 '.' 배치)"
      fi
      if [[ "$home_result" == "취악" ]]; then
        echo "- /root 디렉터리를 생성하고 소원자를 root:root로, 권한은 700으로 설정하세요."
        echo "  예: mkdir /root && chown root:root /root && chmod 700 /root"
      fi
      echo ""
    fi
  } > "$LOG_FILE"
}

# U-06: 파일 및 디렉터리 소유자 설정 
check_u06() {
  LOG_FILE="$LOG_DIR/U-06.txt"

  {
    echo "=================================================================="
    echo "  취약점 코드        : [U-06]"
    echo "  진단 항목          : 파일 및 디렉터리 소유자 설정"
    echo "  위험도             : 상"
    echo "------------------------------------------------------------------"
    echo "  [점검 결과]"

    nouser_output=$(find / -nouser 2>/dev/null)
    nogroup_output=$(find / -nogroup 2>/dev/null)
    nouser_count=$(echo "$nouser_output" | grep -v '^$' | wc -l)
    nogroup_count=$(echo "$nogroup_output" | grep -v '^$' | wc -l)
    total=$((nouser_count + nogroup_count))

    if [ -z "$nouser_output" ] && [ -z "$nogroup_output" ]; then
        echo "  - 점검 결과         : 경로 접근 불가 또는 파일 없음"
        echo "    설정 내용         : (find 명령 결과 없음)"
        final_result="취약"
    elif [ "$total" -eq 0 ]; then
        echo "  - 소유자 없는 파일 : 없음"
        echo "    설정 내용         : (없음)"
        final_result="양호"
    else
        echo "  - 소유자 없는 파일 : ${nouser_count}건"
        echo "    설정 내용         :"
        echo "$nouser_output" | sed 's/^/      /'
        echo "  - 그룹 없는 파일   : ${nogroup_count}건"
        echo "    설정 내용         :"
        echo "$nogroup_output" | sed 's/^/      /'
        final_result="취약"
    fi

    echo "------------------------------------------------------------------"
    echo "  최종 진단 결과     : $final_result"
    echo "=================================================================="

    if [ "$final_result" = "취약" ]; then
      echo ""
      echo "[취약 사유 상세 설명]"
      if [ -z "$nouser_output" ] && [ -z "$nogroup_output" ]; then
        echo "- 시스템 전체 또는 일부 디렉터리에 접근 권한이 없어 점검을 완료하지 못했습니다."
        echo "- 이는 파일 시스템의 마운트 문제, find 명령 제한, 또는 권한 문제일 수 있으며 보안 점검이 누락될 수 있습니다."
      else
        echo "- 시스템에 소유자(nouser) 또는 그룹(nogroup)이 존재하지 않는 파일이 발견됨."
        echo "- 해당 파일은 퇴직자 계정 잔재, 해킹 시 생성된 악성 파일, 관리 소홀 등으로 발생할 수 있음."
        echo "- 이 파일들은 UID 또는 GID가 동일한 새로운 계정을 생성함으로써 비인가자가 소유자로 인식되어 접근 및 조작 가능성이 존재함."
        echo "- 이는 시스템 중요 파일 위변조, 정보 유출 등의 보안 사고로 이어질 수 있음."
      fi
      echo ""
      echo "[조치 권고 사항]"
      if [ -z "$nouser_output" ] && [ -z "$nogroup_output" ]; then
        echo "- 시스템 루트(/) 또는 특정 디렉터리에 대한 접근 권한 및 마운트 상태를 확인하고,"
        echo "  이후 find 명령을 정상적으로 수행할 수 있도록 조치하십시오."
      else
        echo "- 불필요한 파일은 삭제하고, 필요한 파일의 경우 'chown 사용자:그룹 파일명' 명령으로 소유자 및 그룹을 적절히 재지정하십시오."
      fi
    fi
  } > "$LOG_FILE"
}

# U-07 : /etc/passwd 파일 소유자 및 권한 설정
check_u07() {
  local LOG_FILE="$LOG_DIR/U-07.txt"
  local file="/etc/passwd"
  local risk="상"
  local final_result="양호"

  {
    echo "=================================================================="
    echo "  취약점 코드        : [U-07]"
    echo "  진단 항목          : /etc/passwd 파일 소유자 및 권한 설정"
    echo "  위험도             : $risk"
    echo "------------------------------------------------------------------"
    echo "  [점검 결과]"

    if [ ! -f "$file" ]; then
        echo "  - $file 파일 없음 (취약)"
        final_result="취약"
    else
        local owner=$(stat -c '%U' "$file")
        local perm=$(stat -c '%a' "$file")

        echo "  - 파일 소유자       : $owner"
        echo "    설정 내용         : $(stat -c '%U %G' "$file")"
        echo "  - 파일 권한         : $perm"
        echo "    설정 내용         : $(stat -c '%A' "$file")"

        if [[ "$owner" != "root" || "$perm" -gt 644 ]]; then
            final_result="취약"
        fi
    fi

    echo "------------------------------------------------------------------"
    echo "  최종 진단 결과     : $final_result"
    echo "=================================================================="

    if [[ "$final_result" == "취약" ]]; then
      echo ""
      echo "[취약 사유 상세 설명]"
      if [ ! -f "$file" ]; then
        echo "- /etc/passwd 파일이 존재하지 않아 시스템 계정 정보를 확인할 수 없음. 이는 심각한 보안 상태임."
      else
        echo "- /etc/passwd 파일의 소유자가 root가 아니거나 권한이 644보다 높아 보안상 위험함."
        echo "- 잘못된 소유자 또는 과도한 권한은 비인가자가 시스템 계정 정보를 수정할 수 있는 경로가 됨."
      fi
      echo ""
      echo "[조치 권고 사항]"
      if [ ! -f "$file" ]; then
        echo "- /etc/passwd 파일이 삭제되었거나 손상되었으므로, 백업에서 복원하거나 OS 재설치가 필요함."
      else
        echo "- /etc/passwd 파일의 소유자를 root로, 권한을 644 이하로 설정해야 함."
        echo "  예: chown root:root /etc/passwd"
        echo "      chmod 644 /etc/passwd"
      fi
    fi

    echo ""
  } > "$LOG_FILE"
}
# U-08 : /etc/shadow 파일 소유자 및 권한 설정 
check_u08() {
  local LOG_FILE="$LOG_DIR/U-08.txt"
  local file="/etc/shadow"
  local final_result="양호"

  {
    echo "=================================================================="
    echo "  취약점 코드        : [U-08]"
    echo "  진단 항목          : /etc/shadow 파일 소유자 및 권한 설정"
    echo "  위험도             : 상"
    echo "------------------------------------------------------------------"
    echo "  [점검 결과]"

    if [ ! -f "$file" ]; then
      echo "  - $file 파일 없음 (취약)"
      final_result="취약"
    else
      local owner=$(stat -c '%U' "$file")
      local perm=$(stat -c '%a' "$file")

      echo "  - 파일 소유자       : $owner"
      echo "    설정 내용         : $(stat -c '%U %G' "$file")"
      echo "  - 파일 권한         : $perm"
      echo "    설정 내용         : $(stat -c '%A' "$file")"

      if [[ "$owner" != "root" || "$perm" -gt 400 ]]; then
        final_result="취약"
      fi
    fi

    echo "------------------------------------------------------------------"
    echo "  최종 진단 결과     : $final_result"
    echo "=================================================================="

    if [[ "$final_result" == "취약" ]]; then
      echo ""
      echo "[취약 사유 상세 설명]"
      if [ ! -f "$file" ]; then
        echo "- /etc/shadow 파일이 존재하지 않아 사용자 암호 정보 관리가 불가능함. 이는 시스템 보안에 심각한 결함임."
      else
        echo "- /etc/shadow 파일의 소유자가 root가 아니거나 권한이 400을 초과함."
      fi
      echo ""
      echo "[조치 권고 사항]"
      if [ ! -f "$file" ]; then
        echo "- /etc/shadow 파일을 복구하거나 시스템을 재설치해야 할 수 있음."
      else
        echo "- 파일 소유자를 root로, 권한을 400 이하로 설정하세요:"
        echo "  예: chown root:root /etc/shadow"
        echo "      chmod 400 /etc/shadow"
      fi
    fi
    echo ""
  } > "$LOG_FILE"
}
# U-09 : /etc/hosts 파일 소유자 및 권한 설정
check_u09() {
  local LOG_FILE="$LOG_DIR/U-09.txt"
  local file="/etc/hosts"
  local final_result="양호"

  {
    echo "=================================================================="
    echo "  취약점 코드        : [U-09]"
    echo "  진단 항목          : /etc/hosts 파일 소유자 및 권한 설정"
    echo "  위험도             : 상"
    echo "------------------------------------------------------------------"
    echo "  [점검 결과]"

    if [ ! -f "$file" ]; then
      echo "  - $file 파일 없음"
      final_result="취약"
    else
      local owner=$(stat -c '%U' "$file")
      local perm=$(stat -c '%a' "$file")

      echo "  - 파일 소유자       : $owner"
      echo "    설정 내용         : $(stat -c '%U %G' "$file")"
      echo "  - 파일 권한         : $perm"
      echo "    설정 내용         : $(stat -c '%A' "$file")"

      if [[ "$owner" != "root" || "$perm" -gt 600 ]]; then
        final_result="취약"
      fi
    fi

    echo "------------------------------------------------------------------"
    echo "  최종 진단 결과     : $final_result"
    echo "=================================================================="

    if [[ "$final_result" == "취약" ]]; then
      echo ""
      echo "[취약 사유 상세 설명]"
      if [ ! -f "$file" ]; then
        echo "- /etc/hosts 파일이 존재하지 않아 시스템 호스트명 및 IP 매핑 정보가 없거나 관리되지 않고 있습니다."
      else
        echo "- /etc/hosts 파일의 소유자가 root가 아니거나 권한이 600보다 느슨함."
      fi
      echo ""
      echo "[조치 권고 사항]"
      if [ ! -f "$file" ]; then
        echo "- /etc/hosts 파일을 생성하거나 복구하고, 적절한 소유자(root)와 권한(600 이하)을 설정하십시오."
      else
        echo "- 소유자를 root:root로, 권한을 600 이하로 설정하세요:"
        echo "  예: chown root:root /etc/hosts"
        echo "      chmod 600 /etc/hosts"
      fi
    fi
    echo ""
  } > "$LOG_FILE"
}

# U-10 : /etc/(x)inetd.conf 파일 소유자 및 권한 설정
check_u10() {
  local LOG_FILE="$LOG_DIR/U-10.txt"
  local final_result="양호"
  local details=()
  local vulnerable=0
  local files=("/etc/inetd.conf" "/etc/xinetd.conf")

  {
    echo "=================================================================="
    echo "  취약점 코드        : [U-10]"
    echo "  진단 항목          : inetd/xinetd 설정 파일 소유자 및 권한 설정"
    echo "  위험도             : 상"
    echo "------------------------------------------------------------------"
    echo "  [점검 결과]"

    for file in "${files[@]}"; do
      if [ ! -e "$file" ]; then
        echo "  - $file 파일 없음 (취약)"
        vulnerable=1
        continue
      fi

      owner=$(stat -c "%U" "$file")
      perm=$(stat -c "%a" "$file")

      echo "  - $file 소유자       : $owner"
      echo "    설정 내용           : $(stat -c '%U %G' "$file")"
      echo "  - $file 권한         : $perm"
      echo "    설정 내용           : $(stat -c '%A' "$file")"

      if [[ "$owner" != "root" || "$perm" -gt 600 ]]; then
        vulnerable=1
      fi
    done

    final_result=$([[ "$vulnerable" -eq 1 ]] && echo "취약" || echo "양호")

    echo "------------------------------------------------------------------"
    echo "  최종 진단 결과     : $final_result"
    echo "=================================================================="

    if [ "$final_result" = "취약" ]; then
      echo ""
      echo "[취약 사유 상세 설명]"
      for file in "${files[@]}"; do
        if [ ! -e "$file" ]; then
          echo "- $file 파일이 존재하지 않아 점검 불가 또는 삭제된 상태"
        else
          owner=$(stat -c "%U" "$file")
          perm=$(stat -c "%a" "$file")
          if [ "$owner" != "root" ]; then
            echo "- $file 파일의 소유자가 root가 아님 → 현재: $owner"
          fi
          if [ "$perm" -gt 600 ]; then
            echo "- $file 파일의 권한이 600 초과 → 현재: $perm"
          fi
        fi
      done

      echo ""
      echo "[조치 권고 사항]"
      echo "- 해당 설정 파일의 소유자를 root로 지정하고 권한을 600 이하로 제한하세요:"
      echo "  예: chown root:root /etc/inetd.conf /etc/xinetd.conf"
      echo "      chmod 600 /etc/inetd.conf /etc/xinetd.conf"
    fi
    echo ""
  } > "$LOG_FILE"
}

# U-11 : /etc/syslog.conf 파일 소유자 및 권한 설정 
check_u11() {
  LOG_FILE="$LOG_DIR/U-11.txt"
  CHECK_ID="U-11"
  CHECK_TITLE="/etc/syslog.conf 파일 소유자 및 권한 설정"
  SEVERITY="상"

  FILE="/etc/syslog.conf"
  ALT_FILE="/etc/rsyslog.conf"

  TARGET_FILE=""
  FILE_FOUND="false"
  FINAL_RESULT="양호"

  {
    echo "=================================================================="
    echo "  취약점 코드        : [$CHECK_ID]"
    echo "  진단 항목          : $CHECK_TITLE"
    echo "  위험도             : $SEVERITY"
    echo "------------------------------------------------------------------"
    echo "  [점검 결과]"

    if [ -f "$FILE" ]; then
        TARGET_FILE="$FILE"
        FILE_FOUND="true"
    elif [ -f "$ALT_FILE" ]; then
        TARGET_FILE="$ALT_FILE"
        FILE_FOUND="true"
    fi

    if [ "$FILE_FOUND" != "true" ]; then
        echo "  - 대상 파일 없음"
        echo "    설정 내용       : $FILE 또는 $ALT_FILE 파일이 존재하지 않음"
        FINAL_RESULT="취약"
    else
        OWNER=$(stat -c %U "$TARGET_FILE")
        PERMS=$(stat -c %a "$TARGET_FILE")

        VALID_OWNERS=("root" "bin" "sys")
        OWNER_VALID="false"
        for valid in "${VALID_OWNERS[@]}"; do
            if [ "$OWNER" == "$valid" ]; then
                OWNER_VALID="true"
                break
            fi
        done

        PERM_VALID="false"
        if [ "$PERMS" -le 640 ]; then
            PERM_VALID="true"
        fi

        echo "  - 점검 대상 파일 : $TARGET_FILE"
        echo "  - 파일 소유자     : $OWNER"
        echo "    설정 내용       : $(stat -c '%U %G' "$TARGET_FILE")"
        echo "  - 파일 권한       : $PERMS"
        echo "    설정 내용       : $(stat -c '%A' "$TARGET_FILE")"

        if [ "$OWNER_VALID" != "true" ] || [ "$PERM_VALID" != "true" ]; then
            FINAL_RESULT="취약"
        fi
    fi

    echo "------------------------------------------------------------------"
    echo "  최종 진단 결과     : $FINAL_RESULT"
    echo "=================================================================="
    echo ""

    if [ "$FINAL_RESULT" = "취약" ]; then
        echo "[취약 사유 상세 설명]"
        if [ "$FILE_FOUND" != "true" ]; then
            echo "- 로그 설정 파일이 존재하지 않아 로그 수집이 불가능한 상태일 수 있습니다."
            echo "- 로그 부재는 보안 사고 발생 시 원인 추적 및 대응에 심각한 지장을 초래합니다."
        else
            if [ "$OWNER_VALID" != "true" ]; then
                echo "- 로그 설정 파일의 소유자가 root/bin/sys 중 하나가 아니며, 비인가 사용자가 수정할 위험이 있습니다."
            fi
            if [ "$PERM_VALID" != "true" ]; then
                echo "- 로그 설정 파일 권한이 640을 초과하여 과도하게 개방되어 있습니다."
                echo "- 이는 로그 파일 위변조 또는 로그 기능 차단 시도로 이어질 수 있습니다."
            fi
        fi
        echo ""
        echo "[조치 권고 사항]"
        if [ "$FILE_FOUND" != "true" ]; then
            echo "- /etc/syslog.conf 또는 /etc/rsyslog.conf 파일이 존재하는지 확인하고, 로그 서비스를 정상적으로 설정하십시오."
        else
            if [ "$OWNER_VALID" != "true" ]; then
                echo "- 로그 설정 파일의 소유자를 root 또는 bin/sys 계정으로 설정하십시오."
                echo "  예: chown root:root $TARGET_FILE"
            fi
            if [ "$PERM_VALID" != "true" ]; then
                echo "- 로그 설정 파일의 권한을 640 이하로 설정하십시오."
                echo "  예: chmod 640 $TARGET_FILE"
            fi
        fi
        echo ""
    fi
  } > "$LOG_FILE"
}

# U-12 : /etc/services 파일 소유자 및 권한 설정
check_u12() {
  LOG_FILE="$LOG_DIR/U-12.txt"
  CODE="U-12"
  TITLE="/etc/services 파일 소유자 및 권한 설정"
  RISK="상"
  FILE="/etc/services"
  GOOD_OWNERS=("root" "bin" "sys")
  GOOD_PERM_MAX=644
  FINAL_RESULT="양호"

  {
    echo "=================================================================="
    echo "  취약점 코드        : [$CODE]"
    echo "  진단 항목          : $TITLE"
    echo "  위험도             : $RISK"
    echo "------------------------------------------------------------------"
    echo "  [점검 결과]"

    if [ ! -e "$FILE" ]; then
      echo "  - 점검 대상 파일 없음"
      echo "    설정 내용 : $FILE 파일이 존재하지 않음"
      FINAL_RESULT="취약"
    else
      OWNER=$(stat -c "%U" "$FILE" 2>/dev/null)
      PERM=$(stat -c "%a" "$FILE" 2>/dev/null)
      OWNER_OK="false"
      PERM_OK="false"

      for VALID_OWNER in "${GOOD_OWNERS[@]}"; do
        if [ "$OWNER" == "$VALID_OWNER" ]; then
          OWNER_OK="true"
          break
        fi
      done

      if [ "$PERM" -le "$GOOD_PERM_MAX" ]; then
        PERM_OK="true"
      fi

      echo "  - 파일 소유자     : $OWNER"
      echo "    설정 내용       : $(stat -c '%U %G' "$FILE")"
      echo "  - 파일 권한       : $PERM"
      echo "    설정 내용       : $(stat -c '%A' "$FILE")"

      if [ "$OWNER_OK" != "true" ] || [ "$PERM_OK" != "true" ]; then
        FINAL_RESULT="취약"
      fi
    fi

    echo "------------------------------------------------------------------"
    echo "  최종 진단 결과     : $FINAL_RESULT"
    echo "=================================================================="
    echo ""

    if [ "$FINAL_RESULT" == "취약" ]; then
      echo "[취약 사유 상세 설명]"
      if [ ! -e "$FILE" ]; then
        echo "- /etc/services 파일이 존재하지 않아 시스템 서비스 포트에 대한 설정 확인이 불가능합니다."
      else
        if [ "$OWNER_OK" != "true" ]; then
          echo "- /etc/services 파일의 소유자가 root, bin, sys 중 하나가 아니며, 비인가 사용자가 수정할 위험이 있습니다."
        fi
        if [ "$PERM_OK" != "true" ]; then
          echo "- /etc/services 파일의 권한이 644 초과로 설정되어 있어 다른 사용자가 내용을 열람하거나 변경할 수 있는 위험이 있습니다."
        fi
      fi
      echo ""
      echo "[조치 권고 사항]"
      if [ ! -e "$FILE" ]; then
        echo "- /etc/services 파일이 누락된 경우, 패키지 재설치 등을 통해 복원하고 기본 설정을 점검해야 합니다."
      else
        if [ "$OWNER_OK" != "true" ]; then
          echo "- 파일 소유자를 root 또는 bin, sys 중 하나로 설정해야 합니다."
          echo "  예: chown root:root $FILE"
        fi
        if [ "$PERM_OK" != "true" ]; then
          echo "- 파일 권한을 644 이하로 설정하여 불필요한 접근을 차단해야 합니다."
          echo "  예: chmod 644 $FILE"
        fi
      fi
      echo ""
    fi
  } > "$LOG_FILE"
}

# U-13 : SUID, SGID, Sticky bit 설정 파일 점검
check_u13() {
  LOG_FILE="$LOG_DIR/U-13.txt"
  CODE="U-13"
  TITLE="SUID, SGID 설정 파일 점검"
  RISK="상"
  FILES=("/usr/bin/passwd" "/usr/bin/sudo" "/bin/ping" "/usr/bin/chage")
  FINAL_RESULT="양호"
  FILE_MISSING=0
  SUID_SGID_FOUND=0

  {
    echo "=================================================================="
    echo "  취약점 코드        : [$CODE]"
    echo "  진단 항목          : $TITLE"
    echo "  위험도             : $RISK"
    echo "------------------------------------------------------------------"
    echo "  [점검 결과]"

    for FILE in "${FILES[@]}"; do
      if [ ! -e "$FILE" ]; then
        echo "  - $FILE : 파일 없음"
        FILE_MISSING=1
        continue
      fi

      PERM=$(ls -l "$FILE" | awk '{print $1}')
      SUID=${PERM:3:1}
      SGID=${PERM:6:1}
      SUID_STATUS="없음"
      SGID_STATUS="없음"

      if [[ "$SUID" == "s" || "$SUID" == "S" ]]; then
        SUID_STATUS="설정됨"
        SUID_SGID_FOUND=1
      fi
      if [[ "$SGID" == "s" || "$SGID" == "S" ]]; then
        SGID_STATUS="설정됨"
        SUID_SGID_FOUND=1
      fi

      echo "  - 파일 경로       : $FILE"
      echo "    권한            : $PERM"
      echo "    SUID 상태       : $SUID_STATUS"
      echo "    SGID 상태       : $SGID_STATUS"
    done

    echo "------------------------------------------------------------------"

    if [[ $FILE_MISSING -eq 1 ]]; then
      FINAL_RESULT="취약"
    elif [[ $SUID_SGID_FOUND -eq 1 ]]; then
      FINAL_RESULT="취약"
    fi

    echo "  최종 진단 결과     : $FINAL_RESULT"
    echo "=================================================================="
    echo ""

    if [[ "$FINAL_RESULT" == "취약" ]]; then
      echo "[취약 사유 상세 설명]"
      if [[ "$FILE_MISSING" -eq 1 ]]; then
        echo "- 주요 시스템 파일 일부가 존재하지 않음"
      fi
      if [[ "$SUID_SGID_FOUND" -eq 1 ]]; then
        echo "- SUID 또는 SGID 설정 파일이 존재함 → 권한 상승 가능성"
      fi

      echo ""
      echo "[조치 권고 사항]"
      echo "- 불필요한 SUID/SGID 권한을 제거하세요:"
      echo "  chmod u-s <파일명>   # SUID 제거"
      echo "  chmod g-s <파일명>   # SGID 제거"
      echo "- 필요 최소 권한 원칙을 적용하세요."
    fi
  } > "$LOG_FILE"
}

# U-14 : 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정
check_u14() {
  LOG_FILE="$LOG_DIR/U-14.txt"
  CODE="U-14"
  TITLE="사용자 환경파일 및 시작파일 권한 점검"
  RISK="상"
  FILES=".profile .kshrc .cshrc .bashrc .bash_profile .login .exrc .netrc"
  FINAL_RESULT="양호"
  FOUND_ISSUE=0

  {
    echo "=================================================================="
    echo "  취약점 코드        : [$CODE]"
    echo "  진단 항목          : $TITLE"
    echo "  위험도             : $RISK"
    echo "------------------------------------------------------------------"
    echo "  [점검 결과]"

    while IFS=: read -r user _ uid _ _ user_home _; do
      [ "$uid" -ge 1000 ] || continue
      echo "  - 사용자: $user"

      for file in $FILES; do
        target="$user_home/$file"
        if [ -e "$target" ]; then
          owner=$(stat -c %U "$target" 2>/dev/null)
          perm=$(stat -c %a "$target" 2>/dev/null)
          others_write=$(stat -c %A "$target" | cut -c 9)
          group_write=$(stat -c %A "$target" | cut -c 6)

          echo "    > 환경파일: $file"
          echo "      - 소유자: $owner"
          echo "      - 권한  : $perm"

          if [ "$owner" != "$user" ] && [ "$owner" != "root" ]; then
            echo "      - 진단  : 취약 (소유자가 사용자 또는 root 아님)"
            FOUND_ISSUE=1
          elif [ "$others_write" = "w" ] || [ "$group_write" = "w" ]; then
            echo "      - 진단  : 취약 (그룹 또는 기타 사용자에 쓰기 권한 있음)"
            FOUND_ISSUE=1
          else
            echo "      - 진단  : 양호"
          fi
        fi
      done
    done < /etc/passwd

    echo "------------------------------------------------------------------"
    FINAL_RESULT=$([[ "$FOUND_ISSUE" -eq 1 ]] && echo "취약" || echo "양호")
    echo "  최종 진단 결과     : $FINAL_RESULT"
    echo "=================================================================="
    echo ""

    if [ "$FINAL_RESULT" == "취약" ]; then
      echo "[취약 사유 상세 설명]"
      echo "- 환경파일 소유자 또는 권한 설정이 부적절하여 보안 위험이 있음"
      echo ""
      echo "[조치 권고 사항]"
      echo "- 환경파일 소유자는 본인 또는 root여야 하며"
      echo "- 그룹 및 기타 사용자에게 쓰기 권한이 없어야 함"
      echo "- chown 사용자명 파일명 / chmod go-w 파일명 사용"
    fi
  } > "$LOG_FILE"
}

# U-15 : world writable 파일 점검
check_u15() {
  local LOG_FILE="$LOG_DIR/U-15.txt"
  local CODE="U-15"
  local TITLE="불필요한 world writable 파일 존재 여부 점검"
  local RISK="상"

  {
    # 전체 world writable 파일 찾기
    local FILES
    FILES=$(find / -xdev -type f -perm -0002 2>/dev/null)
    local FILE_COUNT
    FILE_COUNT=$(echo "$FILES" | grep -v '^$' | wc -l)

    # 중요 시스템 경로 지정
    local CRITICAL_PATHS="/etc /bin /sbin /usr /var /root"
    local CRITICAL_FILES=""
    for path in $CRITICAL_PATHS; do
      CRITICAL_FILES+="$(find "$path" -xdev -type f -perm -0002 2>/dev/null)
"
    done
    local CRITICAL_COUNT
    CRITICAL_COUNT=$(echo "$CRITICAL_FILES" | grep -v '^$' | wc -l)

    # 확인 여부 기록 파일 경로
    local CONFIRM_FILE="/var/log/world_write_confirmed.list"

    local STATUS=""
    if [ "$CRITICAL_COUNT" -eq 0 ]; then
      STATUS="양호"
    else
      local CONFIRMED_COUNT=0
      local UNCONFIRMED_FILES=""
      while IFS= read -r file; do
        if grep -Fxq "$file" "$CONFIRM_FILE" 2>/dev/null; then
          ((CONFIRMED_COUNT++))
        else
          UNCONFIRMED_FILES+="$file
"
        fi
      done <<< "$CRITICAL_FILES"

      if [ "$CONFIRMED_COUNT" -eq "$CRITICAL_COUNT" ]; then
        STATUS="양호"
      else
        STATUS="취약"
      fi
    fi

    echo "=================================================================="
    echo "취약점 코드        : [$CODE]"
    echo "진단 항목          : $TITLE"
    echo "위험도             : $RISK"
    echo "------------------------------------------------------------------"
    echo ""
    echo "[점검 결과]"
    echo "* 전체 world writable 파일 수        : $FILE_COUNT 건"
    echo "* 중요 시스템 경로 내 존재 파일 수     : $CRITICAL_COUNT 건"
    echo "* 중요 시스템 경로 내 존재 파일 목록  :"
    if [ "$CRITICAL_COUNT" -eq 0 ]; then
      echo "  (없음)"
    else
      while IFS= read -r file; do
        if [ -n "$file" ]; then
          if grep -Fxq "$file" "$CONFIRM_FILE" 2>/dev/null; then
            echo "  - $file : 예 (설정 이유 확인됨)"
          else
            echo "  - $file : 아니오 (설정 이유 미확인)"
          fi
        fi
      done <<< "$CRITICAL_FILES"
    fi
    echo ""

    if [ "$FILE_COUNT" -eq 0 ]; then
      echo "* world writable 파일 : 없음"
      echo "  설정 내용 : (해당 파일 없음)"
    else
      echo "* 전체 world writable 파일 목록 및 확인 여부:"
      while IFS= read -r file; do
        if [ -n "$file" ]; then
          if grep -Fxq "$file" "$CONFIRM_FILE" 2>/dev/null; then
            echo "  - $file : 예 (설정 이유 확인됨)"
          else
            echo "  - $file : 아니오 (설정 이유 미확인)"
          fi
        fi
      done <<< "$FILES"
    fi

    echo ""
    echo "---"
    echo ""
    echo "# 최종 진단 결과     : $STATUS"
    echo "=================================================================="
    echo ""

    if [ "$STATUS" == "취약" ]; then
      echo "[취약 사유 상세 설명]"
      echo "- world writable 파일은 모든 사용자가 해당 파일에 쓰기 가능하여"
      echo "  악성코드 삽입, 시스템 파일 변조, 데이터 유출 등의 보안 위협에 노출될 수 있습니다."
      echo "- 이러한 파일이 시스템에 존재하면 권한이 낮은 사용자도 중요한 파일을 조작할 수 있어"
      echo "  루트 권한 탈취로 이어질 수 있습니다."
      echo ""
      echo "[조치 권고 사항]"
      echo "- world writable 파일 중 불필요한 파일은 삭제하거나 쓰기 권한을 제거하십시오."
      echo "- 예시: chmod o-w <파일경로>"
      echo "- 꼭 필요한 경우를 제외하고는 퍼블릭 쓰기 권한은 제거하는 것이 권장됩니다."
      echo "- 다음 명령으로 확인 및 제거 가능:"
      echo "  find / -xdev -type f -perm -0002 -exec chmod o-w {} \\;"
      echo ""
    fi
  } > "$LOG_FILE"
}

# U-16 : /dev에 존재하지 않는 device 파일 점검 
check_u16() {
  local LOG_FILE="$LOG_DIR/U-16.txt"

  {
    echo "=================================================================="
    echo "  취약점 코드        : [U-16]"
    echo "  진단 항목          : dev에 존재하지 않는 device 파일 점검"
    echo "  위험도             : 상"
    echo "------------------------------------------------------------------"

    dev_check="X"
    device_remove_status="미점검"
    diagnosis="취약"
    detailed_reason=""
    removed_files=""
    non_device_list_before=""
    non_device_list_after=""

    dev_files_exist=$(find /dev -type f 2>/dev/null | wc -l)

    if [ "$dev_files_exist" -eq 0 ]; then
      dev_check="X"
      device_remove_status="미점검"
      diagnosis="취약"
      detailed_reason="- /dev 디렉터리에 일반 파일이 존재하지 않아 점검이 수행되지 않았습니다."
    else
      dev_check="O"
      non_device_list_before=$(find /dev -type f -exec stat -c '%n %t:%T' {} + 2>/dev/null | awk '$2=="0:0" {print $1}')
      
      if [ -n "$non_device_list_before" ]; then
        while read -r file; do
          rm -f "$file" 2>/dev/null && removed_files+="$file"$'\n'
        done <<< "$non_device_list_before"

        non_device_list_after=$(find /dev -type f -exec stat -c '%n %t:%T' {} + 2>/dev/null | awk '$2=="0:0" {print $1}')
        
        if [ -z "$non_device_list_after" ]; then
          device_remove_status="제거 완료"
          diagnosis="양호"
          detailed_reason="- 비정상 device 파일을 점검하고 모두 제거하였습니다."
        else
          device_remove_status="방치됨"
          diagnosis="취약"
          detailed_reason="- 비정상 device 파일이 일부 혹은 전부 방치되어 있습니다."
        fi
      else
        device_remove_status="제거 대상 없음"
        diagnosis="취약"
        detailed_reason="- 비정상 device 파일이 존재하지 않아 제거 작업이 수행되지 않았습니다."
      fi
    fi

    echo "  [점검 결과]"
    echo "  - dev 파일 점검 여부           : $dev_check"
    echo "  - 비정상 device 파일 제거 상태 : $device_remove_status"
    echo "  - 세부 사항                    : $detailed_reason"
    if [ "$diagnosis" = "취약" ] && [ -n "$non_device_list_after" ]; then
      echo "  - 현재 남아 있는 비정상 파일 목록:"
      echo "$non_device_list_after" | sed 's/^/    > /'
    fi
    if [ "$diagnosis" = "양호" ]; then
      echo "  - 제거된 비정상 파일 목록:"
      echo "$removed_files" | sed 's/^/    > /'
    fi

    echo "------------------------------------------------------------------"
    echo "  최종 진단 결과     : $diagnosis"
    echo "=================================================================="
    echo
    echo "[취약 사유 상세 설명]"
    if [ "$diagnosis" = "취약" ]; then
      if [ "$dev_check" = "X" ]; then
        echo "- /dev 디렉터리에 일반 파일이 없어 점검이 수행되지 않아 위험을 방지할 수 없습니다."
      elif [ "$device_remove_status" = "제거 대상 없음" ]; then
        echo "- 비정상 device 파일이 존재하지 않아 제거 대상이 없지만, 점검만으로 양호로 판단할 수 없습니다."
      else
        echo "- 비정상 device 파일이 존재하지만 제거되지 않아 시스템 안정성이 위협받고 있습니다."
      fi
      echo "- 디바이스 명 오입력 등으로 생성된 파일은 시스템 오류 및 보안 문제를 유발할 수 있습니다."
    else
      echo "- 비정상 device 파일을 정확히 점검하고 제거하여 시스템 안정성을 확보했습니다."
    fi
    echo
    echo "[조치 권고 사항]"
    if [ "$diagnosis" = "취약" ]; then
      echo "- /dev 디렉터리에 이상 파일이 없더라도 주기적으로 점검하고, 비정상 파일이 발견되면 즉시 제거하십시오."
      echo "- 비정상 device 파일이 존재할 경우 반드시 삭제하고, 생성 권한을 제한하십시오."
    else
      echo "- 현재 상태를 유지하되 정기 점검을 수행하여 이상 파일 생성을 방지하십시오."
    fi
    echo
    echo "=================================================================="
  } > "$LOG_FILE"
}

# U-17 : $HOME/.rhosts, hosts.equiv 사용 금지
check_u17() {
  LOG_FILE="$LOG_DIR/U-17.txt"
  {
    echo "=================================================================="
    echo "  취약점 코드        : U-17"
    echo "  진단 항목          : \$HOME/.rhosts, /etc/hosts.equiv 사용 금지"
    echo "  위험도             : 상"
    echo "------------------------------------------------------------------"
    echo "  [점검 결과]"

    service_check=$(netstat -tulnp 2>/dev/null | grep -E '[:.]exec|[:.]login|[:.]shell')
    if [ -z "$service_check" ]; then
      echo "  - login, shell, exec 서비스 미사용으로 점검 제외 (취약 아님)"
      echo "------------------------------------------------------------------"
      echo "  최종 진단 결과     : 양호"
      echo "=================================================================="
      echo
      echo "[취약 사유 상세 설명]"
      echo "- login, shell, exec 서비스가 사용 중이지 않아 .rhosts 관련 위험 없음"
      echo
      echo "[조치 권고 사항]"
      echo "- 해당 서비스가 비활성화되어 있으므로 조치 불필요"
      exit 0
    fi

    vulnerable=false
    current_user=$(whoami)
    files=("/etc/hosts.equiv" "$HOME/.rhosts")

    for file in "${files[@]}"; do
      if [ -e "$file" ]; then
        owner=$(stat -c "%U" "$file")
        perm=$(stat -c "%a" "$file")
        plus_line_count=$(grep -c '^+' "$file" 2>/dev/null)

        echo "  - 파일: $file"
        echo "    > 소유자: $owner"
        echo "    > 권한: $perm"

        if [[ "$owner" != "root" && "$owner" != "$current_user" ]]; then
          echo "    > 진단: 취약 (소유자가 root 또는 사용자 계정 아님)"
          vulnerable=true
        elif [[ "$perm" -gt 600 ]]; then
          echo "    > 진단: 취약 (권한이 600 초과)"
          vulnerable=true
        elif [[ "$plus_line_count" -gt 0 ]]; then
          echo "    > 진단: 취약 ('+' 허용 설정 존재)"
          vulnerable=true
        else
          echo "    > 진단: 양호"
        fi
      else
        echo "  - 파일: $file 없음 (취약)"
        vulnerable=true
      fi
    done

    echo "------------------------------------------------------------------"
    if [ "$vulnerable" = true ]; then
      echo "  최종 진단 결과     : 취약"
      echo "=================================================================="
      echo
      echo "[취약 사유 상세 설명]"
      echo "- 파일 소유자 오류 / 권한 초과 / '+' 설정 존재 / 파일 부재 중 하나 이상 발생"
      echo
      echo "[조치 권고 사항]"
      echo "- 소유자: root 또는 사용자 본인으로 설정 (예: chown root 파일)"
      echo "- 권한: 600 이하로 설정 (예: chmod 600 파일)"
      echo "- '+' 라인 제거 (예: grep -v '^+' 파일 > tmp && mv tmp 파일)"
    else
      echo "  최종 진단 결과     : 양호"
      echo "=================================================================="
      echo
      echo "[취약 사유 상세 설명]"
      echo "- 설정 기준을 충족하여 취약하지 않음"
      echo
      echo "[조치 권고 사항]"
      echo "- 별도 조치 불필요"
    fi
  } > "$LOG_FILE"
}

# U-18 : 접속 IP 및 포트 제한 
check_u18() {
  LOG_FILE="$LOG_DIR/U-18.txt"
  {
    CODE="U-18"
    TITLE="접속 IP 및 포트 제한"
    RISK="상"
    STATUS=""

    HOSTS_ALLOW="/etc/hosts.allow"
    HOSTS_DENY="/etc/hosts.deny"
    TCP_ALLOW_STATUS="없음"
    TCP_DENY_STATUS="없음"
    IPTABLES_STATUS="없음"
    IPFILTER_STATUS="없음"

    echo "=================================================================="
    echo "  취약점 코드        : [$CODE]"
    echo "  진단 항목          : $TITLE"
    echo "  위험도             : $RISK"
    echo "------------------------------------------------------------------"
    echo "  [점검 결과]"

    # TCP Wrapper
    if [ -f "$HOSTS_DENY" ]; then
      if grep -q "^ALL:ALL" "$HOSTS_DENY"; then
        TCP_DENY_STATUS="ALL:ALL 설정됨"
      else
        TCP_DENY_STATUS="ALL:ALL 없음"
      fi
    else
      TCP_DENY_STATUS="hosts.deny 파일 없음"
    fi

    if [ -f "$HOSTS_ALLOW" ]; then
      if grep -E '^[a-zA-Z0-9_-]+ *: *[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$HOSTS_ALLOW" >/dev/null; then
        TCP_ALLOW_STATUS="IP 제한 설정됨"
      else
        TCP_ALLOW_STATUS="IP 제한 설정 없음"
      fi
    else
      TCP_ALLOW_STATUS="hosts.allow 파일 없음"
    fi

    # iptables
    if command -v iptables &>/dev/null; then
      IPTABLES_RULES=$(iptables -S | grep -E '(-s [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|--dport [0-9]+)')
      if [[ -n "$IPTABLES_RULES" ]]; then
        IPTABLES_STATUS="포트/IP 제한 있음"
      else
        IPTABLES_STATUS="제한 없음"
      fi
    fi

    # ipfilter
    if command -v ipf &>/dev/null; then
      IPF_RULES=$(ipfstat -io 2>/dev/null | grep -v "empty list")
      if [[ -n "$IPF_RULES" ]]; then
        IPFILTER_STATUS="룰 있음"
      else
        IPFILTER_STATUS="룰 없음"
      fi
    fi

    echo "  - TCP Wrapper 상태 : $TCP_DENY_STATUS, $TCP_ALLOW_STATUS"
    echo "  - iptables 상태    : $IPTABLES_STATUS"
    echo "  - ipfilter 상태    : $IPFILTER_STATUS"

    if [[ "$TCP_ALLOW_STATUS" == "IP 제한 설정됨" || \
          "$IPTABLES_STATUS" == "포트/IP 제한 있음" || \
          "$IPFILTER_STATUS" == "룰 있음" ]]; then
      STATUS="양호"
    else
      STATUS="취약"
    fi

    echo "------------------------------------------------------------------"
    echo "  최종 진단 결과     : $STATUS"
    echo "=================================================================="
    echo ""

    if [ "$STATUS" == "취약" ]; then
      echo "[취약 사유 상세 설명]"
      echo "- TCP Wrapper 또는 방화벽에서 접속 IP/포트 제한이 설정되지 않음"
      echo ""
      echo "[조치 권고 사항]"
      echo "- /etc/hosts.allow, hosts.deny 설정을 점검하여 IP 제한 구성"
      echo "- 또는 iptables, ipfilter 등으로 포트 기반 제어 설정"
      echo "- 예시:"
      echo "  echo 'ALL:ALL' >> /etc/hosts.deny"
      echo "  iptables -A INPUT -s 192.168.1.0/24 -p tcp --dport 22 -j ACCEPT"
    else
      echo "[취약 사유 상세 설명]"
      echo "- 접속 IP 또는 포트에 대한 제한 설정이 확인되어 보안 위험이 낮음"
      echo ""
      echo "[조치 권고 사항]"
      echo "- 현재 설정을 유지하거나 강화하십시오"
    fi
  } > "$LOG_FILE"
}

# U-55 : hosts.lpd 파일 소유자 및 권한 설정
check_u55() {
  local LOG_FILE="$LOG_DIR/U-55.txt"
  local ITEM_CODE="U-55"
  local ITEM_NAME="hosts.lpd 파일 소유자 및 권한 설정"
  local RISK_LEVEL="하"
  local STATUS="양호"
  local OWNER=""
  local PERM=""

  {
    echo "=================================================================="
    echo "  취약점 코드        : $ITEM_CODE"
    echo "  진단 항목          : $ITEM_NAME"
    echo "  위험도             : $RISK_LEVEL"
    echo "------------------------------------------------------------------"
    echo "  [점검 결과]"

    if [ ! -e /etc/hosts.lpd ]; then
      echo "  - /etc/hosts.lpd 파일이 존재하지 않음"
      echo "------------------------------------------------------------------"
      echo "  최종 진단 결과     : 양호"
      echo "  취약 사유 상세 설명: hosts.lpd 파일이 삭제되어 있거나 사용되지 않음"
      echo "  조치 권고 사항     : -"
      echo "=================================================================="
      return 0
    fi

    OWNER=$(stat -c %U /etc/hosts.lpd)
    PERM=$(stat -c %a /etc/hosts.lpd)

    echo "  - 파일: /etc/hosts.lpd"
    echo "    > 소유자: $OWNER"
    echo "    > 권한: $PERM"

    if [ "$OWNER" = "root" ] && [ "$PERM" -eq 600 ]; then
      STATUS="양호"
      echo "    > 진단: 양호 (소유자 root, 권한 600으로 설정됨)"
    else
      STATUS="취약"
      echo "    > 진단: 취약 (소유자 또는 권한이 기준에 부적합)"
    fi

    echo "------------------------------------------------------------------"
    echo "  최종 진단 결과     : $STATUS"
    echo "=================================================================="

    if [ "$STATUS" = "취약" ]; then
      echo "[취약 사유 상세 설명]"
      echo "- /etc/hosts.lpd 파일의 소유자가 root가 아니거나 권한이 600이 아님"
      echo "- 비인가 사용자가 파일을 수정하거나 접근할 위험이 존재함"
      echo ""
      echo "[조치 권고 사항]"
      echo "- 파일 소유자를 root로 설정: chown root:root /etc/hosts.lpd"
      echo "- 파일 권한을 600으로 설정: chmod 600 /etc/hosts.lpd"
    fi
  } > "$LOG_FILE"
}

# U-56 : UMASK 설정 관리 
check_u56() {
  local LOG_FILE="$LOG_DIR/U-56.txt"
  local ITEM_CODE="U-56"
  local ITEM_NAME="UMASK 설정 관리"
  local RISK_LEVEL="중"
  local STATUS="양호"
  local CURRENT_UMASK=""
  local CURRENT_UMASK_DEC=""
  local STANDARD_UMASK_DEC=18  # 022
  local FILES=("/etc/profile" "/etc/bashrc" "/etc/login.defs")
  local FILE_MISSING=true
  local UMASK_CONFIG_FOUND=false

  {
    echo "=================================================================="
    echo "  취약점 코드        : $ITEM_CODE"
    echo "  진단 항목          : $ITEM_NAME"
    echo "  위험도             : $RISK_LEVEL"
    echo "------------------------------------------------------------------"
    echo "  [점검 결과]"

    if ! command -v umask &>/dev/null; then
      echo "  - UMASK 명령어 없음"
      STATUS="취약"
      echo "------------------------------------------------------------------"
      echo "  최종 진단 결과     : $STATUS"
      echo "[취약 사유 상세 설명]"
      echo "- UMASK 명령어가 존재하지 않아 기본 권한 설정을 확인할 수 없음"
      echo "[조치 권고 사항]"
      echo "- 정상 쉘 환경 설치 및 umask 설정 확인 필요"
      echo "=================================================================="
      return 0
    fi

    CURRENT_UMASK=$(umask)
    CURRENT_UMASK_DEC=$((8#$CURRENT_UMASK))
    echo "  - 현재 UMASK 값     : $CURRENT_UMASK"

    if [ "$CURRENT_UMASK_DEC" -ge "$STANDARD_UMASK_DEC" ]; then
      echo "    > 진단: 양호 (UMASK 값이 022 이상)"
    else
      STATUS="취약"
      echo "    > 진단: 취약 (UMASK 값이 $CURRENT_UMASK 으로 낮음)"
    fi

    for file in "${FILES[@]}"; do
      if [ -f "$file" ]; then
        FILE_MISSING=false
        if grep -qE '^\s*umask\s+[0-7]{3}' "$file"; then
          UMASK_CONFIG_FOUND=true
        fi
      fi
    done

    if [ "$FILE_MISSING" = true ]; then
      STATUS="취약"
      echo "  - UMASK 설정 파일 없음 (/etc/profile, /etc/bashrc, /etc/login.defs)"
    elif [ "$UMASK_CONFIG_FOUND" = false ]; then
      STATUS="취약"
      echo "  - 설정 파일 내 UMASK 설정 미존재"
    else
      echo "  - UMASK 설정이 파일에 명시되어 있음"
    fi

    echo "------------------------------------------------------------------"
    echo "  최종 진단 결과     : $STATUS"
    echo "=================================================================="

    if [ "$STATUS" = "취약" ]; then
      echo "[취약 사유 상세 설명]"
      if [ "$CURRENT_UMASK_DEC" -lt "$STANDARD_UMASK_DEC" ]; then
        echo "- UMASK 값이 낮게 설정되어 파일 생성 시 과도한 권한 부여 가능성 존재"
      fi
      if [ "$FILE_MISSING" = true ]; then
        echo "- UMASK 설정 파일들이 존재하지 않아 설정 불가"
      elif [ "$UMASK_CONFIG_FOUND" = false ]; then
        echo "- 주요 설정 파일 내에 umask 설정이 존재하지 않음"
      fi
      echo
      echo "[조치 권고 사항]"
      echo "- umask 값을 022 이상으로 설정: 예) umask 022"
      echo "- 다음 중 하나 이상의 설정 파일에 umask 022 추가:"
      echo "  /etc/profile, /etc/bashrc, /etc/login.defs"
    fi
  } > "$LOG_FILE"
}

# U-57 : 홈디렉토리 소유자 및 권한 설정
check_u57() {
  local LOG_FILE="$LOG_DIR/U-57.txt"
  local ITEM_CODE="U-57"
  local ITEM_NAME="홈디렉토리 소유자 및 권한 설정"
  local RISK_LEVEL="중"
  local RESULT="양호"
  local RISK_FOUND=0

  {
    echo "=================================================================="
    echo "  취약점 코드        : $ITEM_CODE"
    echo "  진단 항목          : $ITEM_NAME"
    echo "  위험도             : $RISK_LEVEL"
    echo "------------------------------------------------------------------"
    echo "  [점검 결과]"

    while IFS=: read -r username _ uid _ _ home shell; do
      if [ "$uid" -ge 1000 ]; then
        if [ -d "$home" ]; then
          owner=$(stat -c "%U" "$home")
          perms=$(stat -c "%A" "$home")

          if [ "$owner" != "$username" ] || [[ "$perms" =~ .w....... ]]; then
            echo "  - 사용자: $username"
            echo "    > 홈 디렉토리: $home"
            echo "    > 실제 소유자: $owner"
            echo "    > 권한: $perms"
            echo "    > 진단: 취약 (소유자 불일치 또는 타 사용자 쓰기 권한 있음)"
            RESULT="취약"
            RISK_FOUND=1
          else
            echo "  - 사용자: $username"
            echo "    > 홈 디렉토리: $home"
            echo "    > 소유자 및 권한: 정상"
          fi
        else
          echo "  - 사용자: $username"
          echo "    > 홈 디렉토리: $home"
          echo "    > 진단: 취약 (홈 디렉토리가 존재하지 않음)"
          RESULT="취약"
          RISK_FOUND=1
        fi

        for base_dir in /var /data /opt; do
          if [ -d "$base_dir" ]; then
            for dirpath in "$base_dir"/*; do
              if [ -d "$dirpath" ]; then
                dir_owner=$(stat -c "%U" "$dirpath")
                if [ "$dir_owner" = "$username" ] && [[ "$dirpath" != "$home" ]]; then
                  perms_dir=$(stat -c "%A" "$dirpath")
                  if [[ "$perms_dir" =~ .w....... ]]; then
                    echo "  - 사용자: $username"
                    echo "    > 개별 디렉토리: $dirpath"
                    echo "    > 소유자: $dir_owner"
                    echo "    > 권한: $perms_dir"
                    echo "    > 진단: 취약 (타 사용자 쓰기 권한 있음)"
                    RESULT="취약"
                    RISK_FOUND=1
                  else
                    echo "  - 사용자: $username"
                    echo "    > 개별 디렉토리: $dirpath"
                    echo "    > 소유자 및 권한: 정상"
                  fi
                fi
              fi
            done
          fi
        done
      fi
    done < /etc/passwd

    echo "------------------------------------------------------------------"
    echo "  최종 진단 결과     : $RESULT"

    if [ "$RISK_FOUND" -eq 1 ]; then
      echo "  취약 사유 상세 설명:"
      echo "    - 홈 디렉토리가 없거나 소유자가 다르거나, 타 사용자에게 쓰기 권한이 부여된 경우 존재"
      echo "    - 사용자 홈 디렉토리 외에 사용자가 소유한 다른 디렉토리에도 권한 문제 가능성 있음"
      echo "  조치 권고 사항:"
      echo "    - 사용자별 홈 디렉토리 소유자를 해당 계정으로 변경"
      echo "    - 타 사용자의 쓰기 권한을 제거"
      echo "    - 필요시 사용자 소유 비표준 디렉토리도 권한 점검"
      echo "    - 예: chown 사용자명:그룹명 디렉토리명"
      echo "          chmod 750 디렉토리명"
    else
      echo "  취약 사유 상세 설명: 모든 사용자 홈 및 개별 디렉토리 권한 설정이 적절함"
      echo "  조치 권고 사항     : -"
    fi
    echo "=================================================================="
  } > "$LOG_FILE"
}

# U-58 : 홈디렉토리로 지정한 디렉토리의 존재 관리
check_u58() {
  local LOG_FILE="$LOG_DIR/U-58.txt"
  local ITEM_CODE="U-58"
  local ITEM_NAME="홈디렉토리로 지정한 디렉토리의 존재 관리"
  local RISK_LEVEL="중"
  local RESULT="양호"
  local VULN_FOUND=0

  {
    echo "=================================================================="
    echo "  취약점 코드        : $ITEM_CODE"
    echo "  진단 항목          : $ITEM_NAME"
    echo "  위험도             : $RISK_LEVEL"
    echo "------------------------------------------------------------------"
    echo "  [점검 결과]"

    if [ ! -f /etc/passwd ]; then
      echo "  * /etc/passwd 파일이 존재하지 않습니다. 점검을 진행할 수 없습니다."
      echo "------------------------------------------------------------------"
      echo "  최종 진단 결과     : 점검 불가"
      echo "  사유               : /etc/passwd 파일이 존재하지 않음"
      echo "  개선 방안          : /etc/passwd 파일의 존재 여부 및 손상 여부를 확인해야 합니다."
      echo "=================================================================="
      return 1
    fi

    while IFS=: read -r user _ uid _ _ home shell; do
      if [[ "$uid" -ge 1000 && "$shell" != *nologin* ]]; then
        if [ ! -d "$home" ]; then
          echo "  - 사용자: $user"
          echo "    > 홈 디렉토리: $home"
          echo "    > 진단: 취약 (홈 디렉토리 존재하지 않음)"
          RESULT="취약"
          VULN_FOUND=1
        else
          if [[ "$home" != "/home/$user" ]]; then
            echo "  - 사용자: $user"
            echo "    > 홈 디렉토리: $home"
            echo "    > 진단: 취약 (홈 디렉토리 위치가 /home/사용자명 형식 아님)"
            RESULT="취약"
            VULN_FOUND=1
          else
            echo "  - 사용자: $user"
            echo "    > 홈 디렉토리: $home"
            echo "    > 진단: 양호 (홈 디렉토리 존재 및 위치 적절)"
          fi
        fi
      fi
    done < /etc/passwd

    echo "------------------------------------------------------------------"
    echo "  최종 진단 결과     : $RESULT"

    if [ "$VULN_FOUND" -eq 1 ]; then
      echo "  취약 사유 상세 설명:"
      echo "    - 홈 디렉토리가 없거나, /home/사용자명 형식이 아닌 계정이 존재함"
      echo "    - 홈 디렉토리 미존재 시 보안 및 로그, 설정 파일 관리에 문제 발생 가능"
      echo "    - 비표준 홈 디렉토리 위치는 관리 및 보안 정책상 주의 필요"
      echo "  조치 권고 사항:"
      echo "    - 홈 디렉토리가 없으면 생성 및 소유자/권한 적절히 설정"
      echo "      예: mkdir -p <홈디렉토리>; chown <사용자>:<사용자> <홈디렉토리>"
      echo "    - 홈 디렉토리 위치가 /home/사용자명 형식이 아닌 경우 정책에 맞게 수정하거나 사용자 안내"
      echo "    - 불필요한 계정은 삭제 권고"
    else
      echo "  취약 사유 상세 설명:"
      echo "    - 모든 일반 사용자 계정의 홈 디렉토리가 /home/사용자명 형식으로 정상 존재함"
      echo "  조치 권고 사항     : -"
    fi
    echo "=================================================================="
  } > "$LOG_FILE"
}

# U-59 : 숨겨진 파일 및 디렉토리 검색 및 제거
check_u59() {
  local LOG_FILE="$LOG_DIR/U-59.txt"
  local ITEM_CODE="U-59"
  local ITEM_NAME="숨겨진 파일 및 디렉토리 검색 및 제거"
  local RISK_LEVEL="하"
  local RESULT="양호"
  local suspicious_found=0
  local suspicious_extensions=(".hmac" ".backup" ".tmp" ".bak")

  {
    echo "=================================================================="
    echo "  취약점 코드        : $ITEM_CODE"
    echo "  진단 항목          : $ITEM_NAME"
    echo "  위험도             : $RISK_LEVEL"
    echo "------------------------------------------------------------------"
    echo "  [점검 결과]"

    hidden_items=$(find / -name ".*" \( -type f -o -type d \) 2>/dev/null)

    if [ -z "$hidden_items" ]; then
      echo "  - 숨겨진 파일 및 디렉토리가 발견되지 않았습니다."
    else
      while IFS= read -r item; do
        for ext in "${suspicious_extensions[@]}"; do
          if [[ "$item" == *"$ext" ]]; then
            echo "  - 의심 항목 발견: $item"
            suspicious_found=1
            break
          fi
        done
      done <<< "$hidden_items"

      if [ "$suspicious_found" -eq 0 ]; then
        echo "  - 숨김 항목은 존재하지만, 의심스러운 확장자를 가진 항목은 없습니다."
      fi
    fi

    echo "------------------------------------------------------------------"

    if [ "$suspicious_found" -eq 1 ]; then
      RESULT="취약"
      echo "  최종 진단 결과     : $RESULT"
      echo "  취약 사유 상세 설명:"
      echo "    - 시스템에 불필요하거나 의심스러운 확장자를 가진 숨겨진 파일 및 디렉토리가 존재합니다."
      echo "    - 이러한 항목은 공격자가 백도어, 임시 저장소, 중요 정보 은닉 등에 악용할 수 있어 보안에 위협이 됩니다."
      echo "    - 삭제되지 않고 방치된 경우, 시스템 침해 가능성이 존재합니다."
      echo "  조치 권고 사항:"
      echo "    - 의심 항목의 내용을 확인하고, 필요하지 않은 경우 즉시 삭제하십시오."
      echo "      예: rm -rf <파일 또는 디렉토리 경로>"
      echo "    - 삭제 전 백업이 필요하다면 안전한 위치로 이동 후 삭제를 진행하십시오."
    else
      echo "  최종 진단 결과     : $RESULT"
      echo "  취약 사유 상세 설명:"
      echo "    - 불필요하거나 의심스러운 숨겨진 파일 및 디렉토리가 존재하지 않거나, 삭제되어 보안상 안전한 상태입니다."
      echo "  조치 권고 사항     : -"
    fi

    echo "=================================================================="
  } > "$LOG_FILE"

  return $suspicious_found
}

# <--------------------------- 서비스 관리 ---------------------->
# U-19 : finger 서비스 비활성화
check_u19() {
  local LOG_FILE="$LOG_DIR/U-19.txt"
  {
    echo "-------------------------------------------"
    echo "[U-19] Finger 서비스 비활성화 점검"
    echo "-------------------------------------------"
    if [ -f /etc/xinetd.d/finger ]; then
        if grep -i "disable" /etc/xinetd.d/finger | grep -iq "no"; then
            echo "[✖] finger 서비스가 활성화되어 있습니다. (disable = no)"
            echo "    [기준] finger 서비스는 disable = yes 로 설정해야 합니다."
        else
            echo "[✔] finger 서비스가 비활성화 되어 있습니다. (disable = yes)"
        fi
    else
        echo "[✔] /etc/xinetd.d/finger 파일이 없음 → finger 서비스 미설정"
    fi
    echo ""
  } > "$LOG_FILE"
}

# U-20 : Anonymous FTP 비활성화
check_u20() {
  local LOG_FILE="$LOG_DIR/U-20.txt"
  local FTP_CONF="/etc/vsftpd/vsftpd.conf"

  {
    echo "-------------------------------------------"
    echo "[U-20] Anonymous FTP 접속 제한 점검"
    echo "-------------------------------------------"

    if [ -f "$FTP_CONF" ]; then
        if grep -i "anonymous_enable=NO" "$FTP_CONF" | grep -iqv "^#"; then
            echo "[✔] vsFTP에서 Anonymous FTP 접속이 제한되어 있습니다."
        else
            echo "[✖] vsFTP에서 Anonymous FTP 접속이 허용되어 있습니다."
            echo "    [기준] anonymous_enable=NO 로 설정해야 합니다."
        fi
    else
        echo "[✔] vsFTP 설정 파일이 존재하지 않음 → Anonymous FTP 사용하지 않는 것으로 판단"
    fi

    echo ""
  } > "$LOG_FILE"
}

# U-21 : r 계열 서비스 비활성화
check_u21() {
  local LOG_FILE="$LOG_DIR/U-21.txt"
  local services=("rsh" "rlogin" "rexec")

  {
    echo "-------------------------------------------"
    echo "[U-21] r 계열 서비스 비활성화 점검"
    echo "-------------------------------------------"

    for svc in "${services[@]}"; do
      local file="/etc/xinetd.d/$svc"
      if [ -f "$file" ]; then
        if grep -i "disable" "$file" | grep -iq "no"; then
          echo "[✖] $svc 서비스가 활성화되어 있습니다. (disable = no)"
          echo "    [기준] $svc 서비스는 disable = yes 로 설정해야 합니다."
        else
          echo "[✔] $svc 서비스가 비활성화되어 있습니다. (disable = yes)"
        fi
      else
        echo "[✔] $svc 설정 파일이 없음 → 서비스 미사용"
      fi
    done

    echo ""
  } > "$LOG_FILE"
}

# U-22 : cron 파일 소유자 및 권한설정
check_u22() {
  local LOG_FILE="$LOG_DIR/U-22.txt"
  local CRON_FILES=(
    "/usr/bin/crontab"
    "/etc/cron.allow"
    "/etc/cron.deny"
    "/etc/cron.hourly"
    "/etc/cron.daily"
    "/etc/cron.weekly"
    "/etc/cron.monthly"
    "/var/spool/cron"
    "/var/spool/cron/crontabs"
  )

  {
    echo "-------------------------------------------"
    echo "[U-22] crond 파일 소유자 및 권한 설정 점검"
    echo "-------------------------------------------"

    for path in "${CRON_FILES[@]}"; do
      if [ -e "$path" ]; then
        local PERM
        local OWNER
        PERM=$(stat -c "%a" "$path")
        OWNER=$(stat -c "%U" "$path")

        if [ "$path" == "/usr/bin/crontab" ]; then
          if [ "$PERM" -le 750 ]; then
            echo "[✔] $path - 권한 $PERM, 소유자 $OWNER"
          else
            echo "[✖] $path - 권한 $PERM, 수정 필요"
          fi
        else
          if [ "$OWNER" == "root" ] && [ "$PERM" -le 640 ]; then
            echo "[✔] $path - 권한 $PERM, 소유자 $OWNER"
          else
            echo "[✖] $path - 권한 $PERM 또는 소유자 $OWNER → 수정 필요"
          fi
        fi
      fi
    done

    echo ""
  } > "$LOG_FILE"
}

# U-23 : Dos 공격에 취약한 서비스 비활성화
check_u23() {
  local LOG_FILE="$LOG_DIR/U-23.txt"
  local DOS_SERVICES=("echo" "discard" "daytime" "chargen")
  local PORTS=("123" "53" "161" "162" "25")

  {
    echo "-------------------------------------------"
    echo "[U-23] DoS 공격에 취약한 서비스 비활성화 점검"
    echo "-------------------------------------------"

    for svc in "${DOS_SERVICES[@]}"; do
      for type in "dgram" "stream"; do
        local path="/etc/xinetd.d/${svc}-${type}"
        if [ -f "$path" ]; then
          if grep -i "disable" "$path" | grep -iq "no"; then
            echo "[✖] $svc ($type) 서비스가 활성화되어 있습니다. (disable = no)"
          else
            echo "[✔] $svc ($type) 서비스가 비활성화 되어 있습니다."
          fi
        fi
      done
    done

    echo ""
    echo "[U-23 확장] NTP, DNS, SNMP, SMTP 포트 점검"
    for port in "${PORTS[@]}"; do
      if ss -tuln | grep -q ":$port"; then
        echo "[✖] 포트 $port 가 열려 있습니다. (서비스 실행 중)"
      else
        echo "[✔] 포트 $port 가 닫혀 있습니다."
      fi
    done
    echo ""
  } > "$LOG_FILE"
}

# U-24 : NFS 서비스 비활성화 
check_u24() {
  local LOG_FILE="$LOG_DIR/U-24.txt"
  local NFS_PROCESSES=("nfsd" "statd" "mountd" "lockd")
  local SYSTEMD_SERVICES=("nfs-server" "nfs" "rpcbind" "statd")
  local FOUND_RUNNING=0

  {
    echo "-------------------------------------------"
    echo "[U-24] NFS 서비스 비활성화 점검"
    echo "-------------------------------------------"
    echo "[1] 실행 중인 NFS 관련 프로세스 확인:"
    for PROC in "${NFS_PROCESSES[@]}"; do
      PIDS=$(pgrep -f "$PROC")
      if [ -n "$PIDS" ]; then
        echo "    [✖] $PROC 프로세스 실행 중 (PID: $PIDS)"
        FOUND_RUNNING=1
      else
        echo "    [✔] $PROC 프로세스 미실행"
      fi
    done

    echo ""
    echo "[2] systemd 서비스 상태 확인:"
    for SERVICE in "${SYSTEMD_SERVICES[@]}"; do
      if systemctl list-unit-files | grep -q "^$SERVICE"; then
        STATUS=$(systemctl is-active "$SERVICE" 2>/dev/null)
        ENABLED=$(systemctl is-enabled "$SERVICE" 2>/dev/null)
        if [ "$STATUS" != "inactive" ] || [ "$ENABLED" != "disabled" ]; then
          echo "    [✖] $SERVICE - 상태: $STATUS / 부팅시 실행: $ENABLED"
          FOUND_RUNNING=1
        else
          echo "    [✔] $SERVICE - 상태: $STATUS / 부팅시 실행: $ENABLED"
        fi
      fi
    done

    echo ""
    echo "[3] /etc/exports 파일 공유 설정 확인:"
    if [ -f /etc/exports ]; then
      SHARE_COUNT=$(grep -v '^\s*#' /etc/exports | grep -v '^\s*$' | wc -l)
      if [ "$SHARE_COUNT" -gt 0 ]; then
        echo "    [✖] /etc/exports에 공유 설정이 존재함 ($SHARE_COUNT개 항목)"
        FOUND_RUNNING=1
      else
        echo "    [✔] /etc/exports 존재하나 공유 설정 없음"
      fi
    else
      echo "    [✔] /etc/exports 파일이 존재하지 않음 → NFS 공유 미사용 상태"
    fi

    echo ""
    echo "[4] 레거시 NFS 부팅 스크립트 존재 여부 확인:"
    RC_PATHS=$(find /etc/rc.d /etc/init.d /etc/rc*.d -type f 2>/dev/null | grep -E 'nfs|statd|mountd|lockd')
    if [ -n "$RC_PATHS" ]; then
      echo "    [✖] rc 스크립트에 NFS 관련 항목 존재:"
      echo "$RC_PATHS" | sed 's/^/        - /'
      FOUND_RUNNING=1
    else
      echo "    [✔] NFS 관련 rc 스크립트 없음"
    fi

    echo ""
    echo "-------------------------------------------"
    if [ "$FOUND_RUNNING" -eq 1 ]; then
      echo "[결과] ✖ NFS 관련 서비스 또는 설정이 활성화되어 있습니다. 비활성화 필요"
    else
      echo "[결과] ✔ NFS 관련 서비스가 비활성화되어 있습니다."
    fi
    echo ""
  } > "$LOG_FILE"
}

# U-25 : NFS 접근 통제
check_u25() {
  local LOG_FILE="$LOG_DIR/U-25.txt"
  local EXPORTS_FILE="/etc/exports"

  {
    echo "-------------------------------------------"
    echo "[U-25] NFS 접근 통제 설정 점검"
    echo "-------------------------------------------"

    if [ -f "$EXPORTS_FILE" ]; then
      echo "[✔] /etc/exports 파일이 존재합니다."
      if grep -E '(\s|\t)\*|everyone' "$EXPORTS_FILE" | grep -qv "ro"; then
        echo "[✖] 접근 통제가 없는 NFS 공유 설정이 존재합니다."
        echo "    [기준] '*' 또는 'everyone' 사용 시 'ro' 옵션으로 제한 필요"
      else
        echo "[✔] NFS 접근 통제 설정이 적절하게 구성되어 있습니다."
      fi
    else
      echo "[✔] /etc/exports 파일이 존재하지 않음 → NFS 공유 미사용 상태"
    fi
    echo ""
  } > "$LOG_FILE"
}

# U-26 : automountd 제거 
check_u26() {
  local LOG_FILE="$LOG_DIR/U-26.txt"

  {
    echo "-------------------------------------------"
    echo "[U-26] automountd 서비스 비활성화 점검"
    echo "-------------------------------------------"

    FOUND=0

    echo "[1] automountd 데몬 실행 여부 확인:"
    if ps -ef | grep -v grep | grep -qE "automount|autofs"; then
      ps -ef | grep -E "automount|autofs" | grep -v grep
      echo "    [✖] automountd 또는 autofs 데몬이 실행 중입니다."
      FOUND=1
    else
      echo "    [✔] automountd 관련 데몬이 실행 중이지 않습니다."
    fi

    echo ""
    echo "[2] 레거시 부팅 스크립트(rc.d)에 automount 항목 존재 여부:"
    RC_PATHS=$(find /etc/rc.d /etc/init.d /etc/rc*.d -type f 2>/dev/null | grep -E "automount|autofs")
    if [ -n "$RC_PATHS" ]; then
      echo "    [✖] 다음 경로에 automount 관련 스크립트가 존재합니다:"
      echo "$RC_PATHS" | sed 's/^/        - /'
      FOUND=1
    else
      echo "    [✔] 레거시 부팅 스크립트에 automount 관련 항목이 존재하지 않습니다."
    fi

    echo ""
    echo "[3] systemd 기반 autofs 서비스 상태 확인:"
    if systemctl list-unit-files | grep -q autofs; then
      STATUS=$(systemctl is-active autofs 2>/dev/null)
      ENABLED=$(systemctl is-enabled autofs 2>/dev/null)
      if [ "$STATUS" != "inactive" ] || [ "$ENABLED" != "disabled" ]; then
        echo "    [✖] autofs 서비스 상태: $STATUS / 부팅시 실행: $ENABLED"
        FOUND=1
      else
        echo "    [✔] autofs 서비스가 비활성화되어 있습니다. (상태: $STATUS / $ENABLED)"
      fi
    else
      echo "    [✔] autofs 서비스가 시스템에 설치되어 있지 않음"
    fi

    echo ""
    if [ "$FOUND" -eq 1 ]; then
      echo "[✖] automount 관련 서비스가 활성화되어 있습니다. 사용하지 않는 경우 비활성화 조치가 필요합니다."
    else
      echo "[✔] automount 관련 서비스가 비활성화되어 있습니다."
    fi

    echo ""
  } > "$LOG_FILE"
}

# U-27 : RPC 서비스 확인
check_u27() {
  local LOG_FILE="$LOG_DIR/U-27.txt"
  local FOUND=0
  local XINETD_DIR="/etc/xinetd.d"
  local RPC_SERVICES=("rsh" "rpc" "rstat" "rexec" "rlogin" "rusers" "spray" "ttdbserver" "walld" "rquotad" "kcms_server" "cachefsd")

  {
    echo "-------------------------------------------"
    echo "[U-27] 불필요한 RPC 서비스 실행 여부 점검"
    echo "-------------------------------------------"

    if [ -d "$XINETD_DIR" ]; then
      echo "[1] /etc/xinetd.d 내 RPC 관련 서비스 설정 확인:"
      for svc in "${RPC_SERVICES[@]}"; do
        matches=$(ls "$XINETD_DIR" 2>/dev/null | grep -i "$svc")
        if [ -n "$matches" ]; then
          for file in $matches; do
            if grep -qi 'disable\s*=\s*no' "$XINETD_DIR/$file"; then
              echo "    [✖] $file → disable = no (활성화됨)"
              FOUND=1
            else
              echo "    [✔] $file → disable = yes (비활성화됨)"
            fi
          done
        fi
      done
    else
      echo "    [✔] /etc/xinetd.d 디렉터리가 존재하지 않음 (xinetd 기반 아님)"
    fi

    echo ""
    echo "[2] 활성화된 RPC 관련 데몬 확인:"
    ENABLED=$(systemctl list-units --type=service --state=running | grep -Ei 'rpc|rstat|rexec|rlogin|rusers|spray|ttdbserver|walld|rquotad')
    if [ -n "$ENABLED" ]; then
      echo "$ENABLED" | while read -r line; do
        echo "    [✖] 활성화된 RPC 서비스: $line"
      done
      FOUND=1
    else
      echo "    [✔] 활성화된 RPC 관련 서비스 없음"
    fi

    echo ""
    echo "[3] /etc/inetd.conf 내 RPC 항목 점검:"
    if [ -f /etc/inetd.conf ]; then
      RPC_LINES=$(grep -E "rstatd|rusersd|walld|rpc" /etc/inetd.conf | grep -v '^#')
      if [ -n "$RPC_LINES" ]; then
        echo "$RPC_LINES" | while read -r line; do
          echo "    [✖] inetd 설정: $line"
        done
        FOUND=1
      else
        echo "    [✔] /etc/inetd.conf 내 활성화된 RPC 항목 없음"
      fi
    else
      echo "    [✔] /etc/inetd.conf 파일이 존재하지 않음"
    fi

    echo ""
    echo "-------------------------------------------"
    if [ "$FOUND" -eq 1 ]; then
      echo "[결과] ✖ 불필요한 RPC 관련 서비스가 활성화되어 있습니다."
      echo "        → /etc/xinetd.d, systemctl, inetd.conf 내 RPC 서비스 disable 설정 권장"
    else
      echo "[결과] ✔ 불필요한 RPC 서비스가 비활성화되어 있습니다."
    fi
    echo ""
  } > "$LOG_FILE"
}

# U-28 : NIS, NIS+ 점검
check_u28() {
  local LOG_FILE="$LOG_DIR/U-28.txt"
  local FOUND=0

  {
    echo "-------------------------------------------"
    echo "[U-28] NIS, NIS+ 서비스 비활성화 점검"
    echo "-------------------------------------------"

    echo "[1] NIS 관련 프로세스 점검 (ypserv, ypbind, ypxfrd, rpc.yppasswdd, rpc.ypupdated):"
    local NIS_PROCS=("ypserv" "ypbind" "ypxfrd" "rpc.yppasswdd" "rpc.ypupdated")
    for PROC in "${NIS_PROCS[@]}"; do
      if pgrep -x "$PROC" > /dev/null; then
        echo "    [✖] $PROC 프로세스 실행 중"
        FOUND=1
      else
        echo "    [✔] $PROC 프로세스 미실행"
      fi
    done

    echo ""
    echo "[2] systemctl 등록된 NIS 관련 서비스 확인:"
    local NIS_SERVICES=("ypserv" "ypbind")
    for SERVICE in "${NIS_SERVICES[@]}"; do
      if systemctl list-unit-files | grep -q "^$SERVICE"; then
        local STATE=$(systemctl is-enabled "$SERVICE" 2>/dev/null)
        local STATUS=$(systemctl is-active "$SERVICE" 2>/dev/null)
        if [ "$STATE" != "disabled" ] || [ "$STATUS" != "inactive" ]; then
          echo "    [✖] $SERVICE - 상태: $STATUS / 부팅 시 활성화: $STATE"
          FOUND=1
        else
          echo "    [✔] $SERVICE - 상태: $STATUS / 부팅 시 활성화: $STATE"
        fi
      fi
    done

    echo ""
    echo "[3] 레거시 부팅 스크립트 경로 내 NIS 관련 스크립트 확인:"
    local RC_PATHS=$(find /etc/rc.d /etc/init.d /etc/rc*.d -type f 2>/dev/null | grep -E 'ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated')
    if [ -n "$RC_PATHS" ]; then
      echo "    [✖] 다음 경로에서 NIS 관련 스크립트 발견됨:"
      echo "$RC_PATHS" | sed 's/^/        - /'
      FOUND=1
    else
      echo "    [✔] NIS 관련 레거시 스크립트 없음"
    fi

    echo ""
    echo "-------------------------------------------"
    if [ "$FOUND" -eq 1 ]; then
      echo "[결과] ✖ NIS 또는 NIS+ 관련 서비스가 활성화되어 있습니다."
      echo "        → 사용하지 않는 경우 관련 데몬 종료 및 서비스 비활성화 권장"
    else
      echo "[결과] ✔ NIS/NIS+ 관련 서비스가 비활성화되어 있습니다."
    fi
    echo ""
  } > "$LOG_FILE"
}

# U-29 : tftp, talk 서비스 비활성화
check_u29() {
  local LOG_FILE="$LOG_DIR/U-29.txt"
  local SERVICES=("tftp" "talk" "ntalk")
  local FOUND=0

  {
    echo "-------------------------------------------"
    echo "[U-29] tftp, talk, ntalk 서비스 비활성화 점검"
    echo "-------------------------------------------"

    for svc in "${SERVICES[@]}"; do
      local FILE="/etc/xinetd.d/$svc"
      if [ -f "$FILE" ]; then
        if grep -qi 'disable\s*=\s*no' "$FILE"; then
          echo "[✖] $svc 서비스가 활성화되어 있음 (disable = no)"
          FOUND=1
        else
          echo "[✔] $svc 서비스가 비활성화되어 있음 (disable = yes)"
        fi
      else
        echo "[✔] $svc 설정 파일이 존재하지 않음 → 비활성화 상태로 간주"
      fi
    done

    echo ""
    echo "-------------------------------------------"
    if [ "$FOUND" -eq 1 ]; then
      echo "[결과] ✖ 불필요한 tftp, talk, ntalk 서비스가 활성화되어 있습니다."
      echo "        → 해당 서비스가 필요하지 않다면 disable = yes 설정 또는 파일 삭제 필요"
    else
      echo "[결과] ✔ tftp, talk, ntalk 서비스가 비활성화되어 있습니다."
    fi
    echo ""
  } > "$LOG_FILE"
}

# U-30 : Sendmail 버전 점검
check_u30() {
  local LOG_FILE="$LOG_DIR/U-30.txt"
  local REQUIRED_VERSION="8.15.2"

  {
    echo "-------------------------------------------"
    echo "[U-30] Sendmail 버전 점검"
    echo "-------------------------------------------"

    if ps -ef | grep -v grep | grep -q sendmail; then
      echo "[✔] Sendmail 프로세스가 실행 중입니다."
    else
      echo "[!] Sendmail 프로세스가 실행 중이지 않습니다. (비활성화 상태)"
    fi

    VERSION_OUTPUT=$(sendmail -d0.1 -bt < /dev/null 2>/dev/null | grep "Version")
    if [ -z "$VERSION_OUTPUT" ]; then
      echo "[✖] Sendmail이 설치되어 있지 않거나 버전 정보를 확인할 수 없습니다."
      echo "[결과] 점검 불가 - sendmail 명령어 미존재 또는 권한 부족"
    else
      CURRENT_VERSION=$(echo "$VERSION_OUTPUT" | grep -oP 'Version\s+\K[\d.]+' | head -1)
      echo "[●] 현재 Sendmail 버전: $CURRENT_VERSION"

      vercomp() {
        if [[ $1 == $2 ]]; then return 0; fi
        local IFS=.
        local i ver1=($1) ver2=($2)
        for ((i=${#ver1[@]}; i<${#ver2[@]}; i++)); do ver1[i]=0; done
        for ((i=${#ver2[@]}; i<${#ver1[@]}; i++)); do ver2[i]=0; done
        for ((i=0; i<${#ver1[@]}; i++)); do
          if ((10#${ver1[i]} > 10#${ver2[i]})); then return 1; fi
          if ((10#${ver1[i]} < 10#${ver2[i]})); then return 2; fi
        done
        return 0
      }

      vercomp "$CURRENT_VERSION" "$REQUIRED_VERSION"
      case $? in
        0|1)
          echo "[✔] 양호: Sendmail 버전이 기준 이상입니다. (≥ $REQUIRED_VERSION)"
          ;;
        2)
          echo "[✖] 취약: Sendmail 버전이 기준 미만입니다. (기준: $REQUIRED_VERSION)"
          ;;
      esac
    fi
    echo ""
  } > "$LOG_FILE"
}

# U-31 : 스팸 메일 릴레이 제한 
check_u31() {
  local LOG_FILE="$LOG_DIR/U-31.txt"
  local SENDMAIL_CF="/etc/mail/sendmail.cf"
  local ACCESS_FILE="/etc/mail/access"
  local FOUND=0

  {
    echo "-------------------------------------------"
    echo "[U-31] 스팸 메일 릴레이 제한 점검"
    echo "-------------------------------------------"

    echo "[1] Sendmail 서비스 실행 여부 확인:"
    if ps -ef | grep -v grep | grep -q sendmail; then
        echo "    [✔] Sendmail 서비스가 실행 중입니다."
    else
        echo "    [✔] Sendmail 서비스가 실행 중이지 않습니다."
    fi

    echo ""
    echo "[2] /etc/mail/sendmail.cf 릴레이 제한 설정 확인:"
    if [ -f "$SENDMAIL_CF" ]; then
        if grep -E '^R\$[*]' "$SENDMAIL_CF" | grep -q 'Relaying denied'; then
            echo "    [✔] 릴레이 제한 설정이 적용되어 있습니다. (\"550 Relaying denied\")"
        else
            echo "    [✖] 릴레이 제한 설정이 없습니다. sendmail.cf에 Relaying denied 설정 필요"
            FOUND=1
        fi
    else
        echo "    [✔] sendmail.cf 파일이 존재하지 않습니다. (Sendmail 미사용 가능성)"
    fi

    echo ""
    echo "[3] /etc/mail/access 릴레이 허용 대상 제한 설정 확인:"
    if [ -f "$ACCESS_FILE" ]; then
        echo "    [✔] access 파일 존재. 다음은 예시 항목입니다:"
        grep -v '^#' "$ACCESS_FILE" | grep -v '^$' | head -n 5 | sed 's/^/        /'
    else
        echo "    [✔] access 파일이 존재하지 않습니다. 기본적인 릴레이 제한 정책만 사용 중일 수 있습니다."
    fi

    echo ""
    echo "-------------------------------------------"
    if [ "$FOUND" -eq 0 ]; then
        echo "[결과] ✔ 스팸 메일 릴레이 제한 설정이 적용되어 있습니다."
    else
        echo "[결과] ✖ 스팸 메일 릴레이 제한 설정이 미흡합니다. sendmail.cf에 Relaying 제한 설정 필요."
    fi
    echo ""
  } > "$LOG_FILE"
}

# U-32 : 일반사용자의 Sendmail 실행 방지
check_u32() {
  local LOG_FILE="$LOG_DIR/U-32.txt"
  local SENDMAIL_CF="/etc/mail/sendmail.cf"
  local FOUND=0

  {
    echo "-------------------------------------------"
    echo "[U-32] 일반사용자의 Sendmail 실행 방지 설정 점검"
    echo "-------------------------------------------"

    echo "[1] Sendmail 서비스 실행 여부 확인:"
    if ps -ef | grep -v grep | grep -q sendmail; then
        echo "    [✔] Sendmail 서비스가 실행 중입니다."
    else
        echo "    [✔] Sendmail 서비스가 실행 중이지 않습니다."
    fi

    echo ""
    echo "[2] sendmail.cf 파일 내 PrivacyOptions restrictqrun 설정 확인:"
    if [ -f "$SENDMAIL_CF" ]; then
        PRIVACY_LINE=$(grep -i '^O PrivacyOptions=' "$SENDMAIL_CF")
        if echo "$PRIVACY_LINE" | grep -q "restrictqrun"; then
            echo "    [✔] restrictqrun 옵션이 설정되어 있어 일반 사용자 실행 방지가 적용되어 있습니다."
        else
            echo "    [✖] restrictqrun 옵션이 설정되어 있지 않음"
            FOUND=1
        fi
    else
        echo "    [✔] sendmail.cf 파일이 존재하지 않습니다. (sendmail 미사용 가능성)"
    fi

    echo ""
    echo "-------------------------------------------"
    if [ "$FOUND" -eq 0 ]; then
        echo "[결과] ✔ 일반사용자의 Sendmail 실행 제한 설정이 적용되어 있습니다."
    else
        echo "[결과] ✖ 일반사용자의 Sendmail 실행 제한 설정이 누락되었습니다."
    fi
    echo ""
  } > "$LOG_FILE"
}

# U-33 : DNS 보안 버전 패치 
check_u33() {
  local LOG_FILE="$LOG_DIR/U-33.txt"
  local FOUND=0

  {
    echo "-------------------------------------------"
    echo "[U-33] DNS 보안 버전 패치 점검"
    echo "-------------------------------------------"

    if pgrep -x named >/dev/null 2>&1; then
        echo "    [✔] named 프로세스가 실행 중입니다."
        echo ""
        echo "[2] BIND(named) 버전 확인:"
        VERSION=$(named -v 2>/dev/null)
        if [ -z "$VERSION" ]; then
            echo "    [!] named 명령어로 버전을 확인할 수 없습니다."
            FOUND=1
        else
            echo "    → 현재 BIND 버전: $VERSION"
            if echo "$VERSION" | grep -Eq '8\.|9\.0|9\.1|9\.2|9\.3|9\.4|9\.5|9\.6|9\.7|9\.8|9\.9|9\.10\.0|9\.10\.1|9\.10\.2|9\.10\.3-P1'; then
                echo "    [✖] 해당 BIND 버전은 보안 패치가 적용되지 않은 취약 버전일 수 있습니다."
                FOUND=1
            else
                echo "    [✔] BIND 버전이 비교적 최신이거나 알려진 취약 범위에 포함되지 않음"
            fi
        fi
    else
        echo "    [✔] named 프로세스가 실행 중이지 않음 (DNS 서비스 미사용 상태)"
    fi

    echo ""
    echo "-------------------------------------------"
    if [ "$FOUND" -eq 1 ]; then
        echo "[결과] ✖ DNS 서비스가 실행 중이거나 BIND 버전이 취약할 수 있습니다."
    else
        echo "[결과] ✔ DNS 서비스가 실행되지 않거나 최신 BIND 버전을 사용 중입니다."
    fi
    echo ""
  } > "$LOG_FILE"
}

# U-34 : DNS Zone Transfer 설정 
check_u34() {
  local LOG_FILE="$LOG_DIR/U-34.txt"
  local FOUND=0

  {
    echo "-------------------------------------------"
    echo "[U-34] DNS Zone Transfer 설정 점검"
    echo "-------------------------------------------"

    if [ -f /etc/named.conf ]; then
        echo "[✔] /etc/named.conf 파일이 존재합니다."
        ALLOW_LINE=$(grep -i "allow-transfer" /etc/named.conf | grep -v '^#')
        if [ -n "$ALLOW_LINE" ]; then
            echo "[✔] allow-transfer 설정이 존재합니다:"
            echo "    $ALLOW_LINE"
        else
            echo "[✖] allow-transfer 설정이 존재하지 않음 → 전체 Zone 전송 허용 가능성 있음"
            FOUND=1
        fi
    else
        echo "[✔] /etc/named.conf 파일이 존재하지 않음 (DNS 서비스 미사용 상태일 수 있음)"
    fi

    echo ""
    echo "-------------------------------------------"
    if [ "$FOUND" -eq 0 ]; then
        echo "[결과] ✔ DNS Zone Transfer 설정이 적절히 제한되어 있거나 DNS 서비스를 사용하지 않습니다."
    else
        echo "[결과] ✖ DNS Zone Transfer 설정이 존재하지 않아 보안상 취약할 수 있습니다."
    fi
    echo ""
  } > "$LOG_FILE"
}

# U-35 : 웹서비스 디렉토리 리스팅 제거
check_u35() {
  local LOG_FILE="$LOG_DIR/U-35.txt"
  local HTTPD_CONF="/etc/httpd/conf/httpd.conf"

  {
    echo "-------------------------------------------"
    echo "[U-35] 웹서비스 디렉토리 리스팅 제거 점검"
    echo "-------------------------------------------"

    if [ ! -f "$HTTPD_CONF" ]; then
        echo "[!] Apache 설정 파일($HTTPD_CONF)이 존재하지 않습니다."
    else
        INDEXES=$(grep -i "Options" "$HTTPD_CONF" | grep -v "^#" | grep -i "Indexes")
        if [ -n "$INDEXES" ]; then
            echo "[✖] Indexes 옵션이 활성화되어 있음:"
            echo "$INDEXES"
        else
            echo "[✔] Indexes 옵션이 설정되어 있지 않음 (또는 -Indexes로 비활성화)"
        fi
    fi
    echo ""
  } > "$LOG_FILE"
}

# U-36: 웹 프로세스 권한 제한
check_u36() {
  local LOG_FILE="$LOG_DIR/U-36.txt"
  local HTTPD_CONF="/etc/httpd/conf/httpd.conf"
  local VULN=0

  {
    echo "-------------------------------------------"
    echo "[U-36] 웹서비스 웹 프로세스 권한 제한 점검"
    echo "-------------------------------------------"

    if [ ! -f "$HTTPD_CONF" ]; then
        echo "[!] Apache 설정 파일이 존재하지 않습니다: $HTTPD_CONF"
    else
        USER_SETTING=$(grep -i "^User" "$HTTPD_CONF" | grep -v "^#")
        GROUP_SETTING=$(grep -i "^Group" "$HTTPD_CONF" | grep -v "^#")

        USER_VALUE=$(echo "$USER_SETTING" | awk '{print $2}')
        GROUP_VALUE=$(echo "$GROUP_SETTING" | awk '{print $2}')

        echo "[1] Apache User 설정 확인: $USER_VALUE"
        echo "[2] Apache Group 설정 확인: $GROUP_VALUE"

        if [ "$USER_VALUE" == "root" ]; then
            echo "    [✖] Apache 데몬이 root 권한으로 실행되도록 설정되어 있습니다."
            VULN=1
        else
            echo "    [✔] Apache 데몬이 root가 아닌 계정으로 실행되도록 설정되어 있습니다."
        fi

        if [ "$GROUP_VALUE" == "root" ]; then
            echo "    [✖] Apache 데몬의 그룹이 root로 설정되어 있습니다."
            VULN=1
        else
            echo "    [✔] Apache 데몬의 그룹이 root가 아닌 계정으로 설정되어 있습니다."
        fi
    fi

    echo ""
    if [ "$VULN" -eq 1 ]; then
        echo "[결과] ✖ Apache 데몬이 root 권한으로 실행되도록 설정되어 있습니다."
    else
        echo "[결과] ✔ Apache 데몬이 root 권한으로 실행되지 않도록 설정되어 있습니다."
    fi
  } > "$LOG_FILE"
}
# U-37 : 웹서비스 상위 디렉토리 접근 금지
check_u37() {
  local LOG_FILE="$LOG_DIR/U-37.txt"
  local HTTPD_CONF
  HTTPD_CONF=$(find / -type f -name httpd.conf 2>/dev/null | head -n 1)
  local HTACCESS_PATH="/usr/local/apache2/htdocs/.htaccess"
  local HTPASSWD_PATH="/usr/local/apache2/auth/.htpasswd"
  local FOUND=0

  {
    echo "-------------------------------------------"
    echo "[U-37] 웹서비스 상위 디렉토리 접근 금지 점검"
    echo "-------------------------------------------"

    echo "[1] httpd.conf 내 AllowOverride 설정 확인:"
    if [ -f "$HTTPD_CONF" ]; then
        ALLOW_OVERRIDE=$(grep -i 'AllowOverride' "$HTTPD_CONF" | grep -v '^#' | awk '{print $2}')
        if echo "$ALLOW_OVERRIDE" | grep -qiE 'AuthConfig|All'; then
            echo "    [✔] AllowOverride 설정이 적절하게 되어 있음: $ALLOW_OVERRIDE"
        else
            echo "    [✖] AllowOverride가 AuthConfig 또는 All이 아님: $ALLOW_OVERRIDE"
            FOUND=1
        fi
    else
        echo "    [✖] httpd.conf 파일을 찾을 수 없음"
        FOUND=1
    fi

    echo ""
    echo "[2] .htaccess 파일 존재 확인:"
    if [ -f "$HTACCESS_PATH" ]; then
        echo "    [✔] .htaccess 파일 존재: $HTACCESS_PATH"
    else
        echo "    [✖] .htaccess 파일이 존재하지 않음 → 인증 설정 미적용"
        FOUND=1
    fi

    echo ""
    echo "[3] .htpasswd 파일 및 사용자 계정 확인:"
    if [ -f "$HTPASSWD_PATH" ]; then
        USER_COUNT=$(grep -c '^[^:]\+:' "$HTPASSWD_PATH")
        if [ "$USER_COUNT" -ge 1 ]; then
            echo "    [✔] .htpasswd에 사용자 계정 $USER_COUNT개 등록됨"
        else
            echo "    [✖] .htpasswd 파일에 유효한 사용자 계정이 없음"
            FOUND=1
        fi
    else
        echo "    [✖] .htpasswd 파일이 존재하지 않음"
        FOUND=1
    fi

    echo ""
    if [ "$FOUND" -eq 0 ]; then
        echo "[결과] ✔ 상위 디렉토리 접근이 제한되도록 적절히 설정되어 있습니다."
    else
        echo "[결과] ✖ 상위 디렉토리 접근이 제대로 제한되지 않았습니다."
    fi
  } > "$LOG_FILE"
}
# U-38 : 웹서비스 불필요한 파일 제거
check_u38() {
  local LOG_FILE="$LOG_DIR/U-38.txt"
  local FOUND=0
  local MANUAL_PATHS=(
    "/var/www/manual"
    "/var/www/html/manual"
    "/usr/local/apache2/htdocs/manual"
    "/etc/httpd/manual"
    "/usr/share/httpd/manual"
  )

  {
    echo "-------------------------------------------"
    echo "[U-38] 웹서비스 불필요한 파일 제거 점검"
    echo "-------------------------------------------"

    for DIR in "${MANUAL_PATHS[@]}"; do
      if [ -d "$DIR" ]; then
        echo "    [✖] 불필요한 매뉴얼 디렉터리 존재: $DIR"
        FOUND=1
      fi
    done

    if [ "$FOUND" -eq 0 ]; then
      echo "    [✔] 불필요한 매뉴얼 디렉터리가 존재하지 않음"
    fi

    echo ""
    if [ "$FOUND" -eq 1 ]; then
      echo "[결과] ✖ Apache 설치 시 기본 생성되는 불필요한 디렉터리가 존재합니다."
    else
      echo "[결과] ✔ 불필요한 매뉴얼 디렉터리가 존재하지 않습니다."
    fi
  } > "$LOG_FILE"
}
# U-39 : 웹서비스 링크 사용 금지
check_u39() {
  local LOG_FILE="$LOG_DIR/U-39.txt"
  local HTTPD_CONF="/etc/httpd/conf/httpd.conf"
  local FOUND=0

  {
    echo "-------------------------------------------"
    echo "[U-39] 웹서비스 디렉토리 검색 기능 제한 점검"
    echo "-------------------------------------------"

    if [ ! -f "$HTTPD_CONF" ]; then
      echo "[✖] Apache 설정 파일이 존재하지 않습니다: $HTTPD_CONF"
      FOUND=1
    else
      INDEXES=$(grep -i "Options" "$HTTPD_CONF" | grep -v "^#" | grep -i "Indexes")
      if [ -n "$INDEXES" ]; then
        echo "[✖] Indexes 옵션이 설정되어 있어 디렉토리 목록 열람이 가능함:"
        echo "$INDEXES"
        FOUND=1
      else
        echo "[✔] Options 지시자에 Indexes 설정이 없음 또는 -Indexes로 설정됨"
      fi
    fi

    echo ""
    if [ "$FOUND" -eq 1 ]; then
      echo "[결과] ✖ 디렉토리 검색 기능이 활성화되어 있습니다."
    else
      echo "[결과] ✔ 디렉토리 검색 기능이 비활성화되어 있습니다."
    fi
  } > "$LOG_FILE"
}
# U-40 : 웹서비스 파일 업로드 및 다운로드 제한
check_u40() {
  local LOG_FILE="$LOG_DIR/U-40.txt"
  local HTTPD_CONF="/etc/httpd/conf/httpd.conf"
  local FOUND=0

  {
    echo "-------------------------------------------"
    echo "[U-40] 웹서비스 파일 업로드 및 다운로드 제한"
    echo "-------------------------------------------"

    echo "[1] LimitRequestBody 설정 확인:"
    if [ -f "$HTTPD_CONF" ]; then
      LINES=$(grep -Ei 'LimitRequestBody' "$HTTPD_CONF" | grep -v '^#')
      if [ -z "$LINES" ]; then
        echo "    [✖] LimitRequestBody 설정이 존재하지 않음"
        FOUND=1
      else
        echo "$LINES" | while read -r line; do
          SIZE=$(echo "$line" | grep -o '[0-9]\+')
          if [ "$SIZE" -le 5000000 ]; then
            echo "    [✔] 설정된 LimitRequestBody: $SIZE (5MB 이하)"
          else
            echo "    [✖] 설정된 LimitRequestBody: $SIZE (5MB 초과)"
            FOUND=1
          fi
        done
      fi
    else
      echo "    [✖] $HTTPD_CONF 파일이 존재하지 않음"
      FOUND=1
    fi

    echo ""
    if [ "$FOUND" -eq 1 ]; then
      echo "[결과] ✖ 업로드 및 다운로드 크기 제한이 미흡합니다."
    else
      echo "[결과] ✔ 업로드 및 다운로드 용량 제한이 적절히 설정되어 있습니다."
    fi
  } > "$LOG_FILE"
}

# U-41: 웹서비스 영역 분리
check_u41() {
    httpd_conf=$(find / -name httpd.conf 2>/dev/null | head -1)
    [ -z "$httpd_conf" ] && httpd_conf="/etc/httpd/conf/httpd.conf"

    doc_root=$(grep '^DocumentRoot' "$httpd_conf" | awk '{print $2}' | tr -d '"')
    default_paths=("/usr/local/apache/htdocs" "/var/www/html")

    if [[ " ${default_paths[@]} " =~ " ${doc_root} " ]]; then
        log_result "U-41" "Warn" "기본 DocumentRoot 사용: $doc_root"
    else
        log_result "U-41" "Pass" "별도 DocumentRoot 설정: $doc_root"
    fi
}

# U-60: SSH 서비스 활성화 + Telnet 설치 여부
check_u60() {
    # SSH 활성화 확인
    ssh_status=$(systemctl is-active sshd 2>/dev/null)
    if [ "$ssh_status" == "active" ]; then
        ssh_result="SSH 서비스 활성화됨"
    else
        ssh_result="SSH 서비스 비활성화됨"
    fi

    # Telnet 패키지 설치 여부 확인
    telnet_installed=$(rpm -q telnet-server telnet 2>/dev/null | grep -v "not installed")
    if [ -n "$telnet_installed" ]; then
        telnet_result="Telnet 설치됨: $(echo "$telnet_installed" | tr '\n' ' ')"
        log_result "U-60" "Warn" "$ssh_result, $telnet_result"
    else
        log_result "U-60" "Pass" "$ssh_result, Telnet 미설치"
    fi
}

# U-61: FTP 서비스 비활성화
check_u61() {
    ftp_status=$(systemctl is-active vsftpd 2>/dev/null)
    if [ "$ftp_status" == "active" ]; then
        log_result "U-61" "Warn" "FTP 서비스 실행 중"
    else
        log_result "U-61" "Pass" "FTP 서비스 미실행"
    fi
}

# U-62: FTP 계정 shell 제한
check_u62() {
    ftp_shell=$(grep '^ftp:' /etc/passwd | cut -d: -f7)
    if [[ "$ftp_shell" == "/sbin/nologin" || "$ftp_shell" == "/bin/false" ]]; then
        log_result "U-62" "Pass" "FTP 계정 쉘 제한됨"
    else
        log_result "U-62" "Warn" "FTP 계정 쉘 활성화: $ftp_shell"
    fi
}

# U-63: ftpusers 파일 권한
check_u63() {
    ftpusers_file=$(find / -name ftpusers 2>/dev/null | head -1)
    if [ -n "$ftpusers_file" ]; then
        perm=$(stat -c "%a" "$ftpusers_file")
        if [ "$perm" -le 640 ]; then
            log_result "U-63" "Pass" "적절한 권한: $ftpusers_file ($perm)"
        else
            log_result "U-63" "Warn" "취약한 권한: $ftpusers_file ($perm)"
        fi
    else
        log_result "U-63" "Warn" "ftpusers 파일 없음"
    fi
}

# U-64: ftpusers 설정 확인
check_u64() {
    ftpusers_file=$(find / -name ftpusers 2>/dev/null | head -1)
    if [ -n "$ftpusers_file" ] && grep -q "^root$" "$ftpusers_file"; then
        log_result "U-64" "Pass" "root 계정 차단 설정됨"
    else
        log_result "U-64" "Warn" "root 계정 미차단"
    fi
}

# U-65: at 파일 권한
check_u65() {
    at_files=("/etc/at.deny" "/etc/at.allow")
    for file in "${at_files[@]}"; do
        if [ -f "$file" ]; then
            perm=$(stat -c "%a" "$file")
            [ "$perm" -gt 640 ] && log_result "U-65" "Warn" "취약한 권한: $file ($perm)"
        fi
    done
}

# U-66: SNMP 서비스 확인
check_u66() {
    if systemctl is-active snmpd &>/dev/null; then
        log_result "U-66" "Warn" "SNMP 서비스 실행 중"
    else
        log_result "U-66" "Pass" "SNMP 서비스 미실행"
    fi
}

# U-67: SNMP 커뮤니티 스트링
check_u67() {
    snmp_conf=$(find / -name snmpd.conf 2>/dev/null | head -1)
    if [ -n "$snmp_conf" ] && grep -q "public\|private" "$snmp_conf"; then
        log_result "U-67" "Warn" "기본 커뮤니티 스트링 사용"
    fi
}

# U-68: 로그온 경고 메시지
check_u68() {
    local vulnerable=0

    # /etc/motd 확인
    if [ ! -f /etc/motd ]; then
        log_result "U-68" "Warn" "/etc/motd 파일이 없습니다."
        vulnerable=1
    elif [ "$(grep -vE '^ *#|^$' /etc/motd | wc -l)" -eq 0 ]; then
        log_result "U-68" "Warn" "/etc/motd에 로그온 메시지가 없습니다."
        vulnerable=1
    fi

    # Telnet 활성 여부 확인 후 /etc/issue.net 확인
    if ps -ef | grep -i telnet | grep -v grep >/dev/null 2>&1 || netstat -nat | grep -q ':23 '; then
        if [ ! -f /etc/issue.net ]; then
            log_result "U-68" "Warn" "Telnet 활성 상태에서 /etc/issue.net 파일이 없습니다."
            vulnerable=1
        elif [ "$(grep -vE '^ *#|^$' /etc/issue.net | wc -l)" -eq 0 ]; then
            log_result "U-68" "Warn" "Telnet 활성 상태에서 /etc/issue.net 메시지가 없습니다."
            vulnerable=1
        fi
    fi

    # FTP 프로세스 존재 시 배너 설정 확인
    if ps -ef | grep -i ftp | grep -vE 'grep|tftp|sftp' >/dev/null 2>&1; then
        local ftp_conf_files=0

        if [ -f /etc/vsftpd.conf ]; then
            ftp_conf_files=$((ftp_conf_files+1))
            if ! grep -vE '^#|^\s#' /etc/vsftpd.conf | grep -q 'ftpd_banner'; then
                log_result "U-68" "Warn" "/etc/vsftpd.conf에 ftpd_banner 설정 없음"
                vulnerable=1
            fi
        fi

        if [ -f /etc/proftpd/proftpd.conf ]; then
            ftp_conf_files=$((ftp_conf_files+1))
            if ! grep -vE '^#|^\s#' /etc/proftpd/proftpd.conf | grep -q 'ServerIdent'; then
                log_result "U-68" "Warn" "/etc/proftpd/proftpd.conf에 ServerIdent 설정 없음"
                vulnerable=1
            fi
        fi

        if [ -f /etc/pure-ftpd/conf/WelcomeMsg ]; then
            ftp_conf_files=$((ftp_conf_files+1))
            if [ "$(grep -vE '^ *#|^$' /etc/pure-ftpd/conf/WelcomeMsg | wc -l)" -eq 0 ]; then
                log_result "U-68" "Warn" "/etc/pure-ftpd/conf/WelcomeMsg 메시지 없음"
                vulnerable=1
            fi
        fi

        if [ $ftp_conf_files -eq 0 ]; then
            log_result "U-68" "Warn" "FTP 프로세스 존재하나 설정 파일 없음"
            vulnerable=1
        fi
    fi

    # SMTP (sendmail) 프로세스 존재 시 greeting 설정 확인
    if ps -ef | grep -i sendmail | grep -v grep >/dev/null 2>&1; then
        local sendmail_files=($(find / -name sendmail.cf 2>/dev/null))
        if [ ${#sendmail_files[@]} -eq 0 ]; then
            log_result "U-68" "Warn" "sendmail 프로세스 존재, sendmail.cf 없음"
            vulnerable=1
        else
            for cf in "${sendmail_files[@]}"; do
                if ! grep -vE '^#|^\s#' "$cf" | grep -q 'GreetingMessage'; then
                    log_result "U-68" "Warn" "$cf 파일에 GreetingMessage 설정 없음"
                    vulnerable=1
                fi
            done
        fi
    fi

    # 최종 결과
    if [ "$vulnerable" -eq 0 ]; then
        log_result "U-68" "Pass" "로그온 경고 메시지 설정 양호"
    fi
}

# U-69: NFS 접근 제한 (소유자 및 권한 확인)
check_u69() {
    nfs_files=("/etc/exports" "/etc/exports.d/*.exports")
    vulnerable=0

    for file in $nfs_files; do
        if [ -f "$file" ]; then
            # 소유자 확인
            owner=$(stat -c "%U" "$file")
            # 권한 확인 (8진수)
            perm=$(stat -c "%a" "$file")
            
            if [ "$owner" != "root" ]; then
                log_result "U-69" "Warn" "$file 소유자 비정상: $owner"
                vulnerable=1
            fi
            
            if [ "$perm" -gt 644 ]; then
                log_result "U-69" "Warn" "$file 권한 취약: $perm"
                vulnerable=1
            fi
        fi
    done

    if [ "$vulnerable" -eq 0 ]; then
        log_result "U-69" "Pass" "NFS 설정 파일 소유자 및 권한 적절"
    fi
}

# U-70: Sendmail expn/vrfy 제한
check_u70() {
    sendmail_cf=$(find / -name sendmail.cf 2>/dev/null | head -1)
    if [ -n "$sendmail_cf" ] && grep -q "PrivacyOptions" "$sendmail_cf"; then
        log_result "U-70" "Pass" "expn/vrfy 명령어 제한됨"
    else
        log_result "U-70" "Warn" "expn/vrfy 설정 미확인"
    fi
}

# U-71: Apache 버전 정보 숨김
check_u71() {
    httpd_conf=$(find / -name httpd.conf 2>/dev/null | head -1)
    if [ -n "$httpd_conf" ]; then
        tokens=$(grep -i "ServerTokens Prod" "$httpd_conf")
        sig=$(grep -i "ServerSignature Off" "$httpd_conf")
        [ -n "$tokens" ] && [ -n "$sig" ] && log_result "U-71" "Pass" "서버 정보 숨김 설정됨" || log_result "U-71" "Warn" "서버 정보 노출 가능"
    fi
}
# <--------------------------- 패치치 관리 ---------------------->

# U-42 : 최신 보안패치 및 벤더 권고사항 적용
check_u42() {
  local LOG_FILE="$LOG_DIR/U-42.txt"
  local ITEM_CODE="[U-42]"
  local ITEM_NAME="최신 보안패치 및 벤더 권고사항 적용"
  local RISK_LEVEL="중"
  local STATUS="취약"
  local PATCH_POLICY_STATUS="확인 불가"
  local PATCH_POLICY_DETAIL="(정보 없음)"
  local PATCH_APPLIED_STATUS="확인 불가"
  local PATCH_APPLIED_DETAIL="(정보 없음)"
  local PATCH_LIST=""
  local APPLIED_PATCH_LIST=""
  local LAST_PATCH_DATE="정보 없음"
  local DAYS_AGO_30
  local PATCH_COUNT=0
  local APPLIED_PATCH_COUNT=0

  DAYS_AGO_30=$(date -d "30 days ago" +%s)

  {
    echo "=================================================================="
    echo "취약점 코드        : $ITEM_CODE"
    echo "진단 항목          : $ITEM_NAME"
    echo "위험도             : $RISK_LEVEL"
    echo "------------------------------------------------------------------"
    echo "  [점검 결과]"

    # 패치 정책 설정 여부 확인
    if [ -f /etc/redhat-release ]; then
      POLICY_FILE="/etc/yum.repos.d/redhat.repo"
      if [ -f "$POLICY_FILE" ]; then
        PATCH_POLICY_STATUS="설정됨"
        PATCH_POLICY_DETAIL="사용 중인 정책 파일: $POLICY_FILE"
      else
        PATCH_POLICY_STATUS="미설정"
      fi
    elif [ -f /etc/debian_version ]; then
      POLICY_FILE="/etc/apt/sources.list"
      if [ -f "$POLICY_FILE" ]; then
        PATCH_POLICY_STATUS="설정됨"
        PATCH_POLICY_DETAIL="사용 중인 정책 파일: $POLICY_FILE"
      else
        PATCH_POLICY_STATUS="미설정"
      fi
    else
      PATCH_POLICY_STATUS="비적용"
    fi

    echo "  - 패치 정책 설정 : $PATCH_POLICY_STATUS"
    echo "    $PATCH_POLICY_DETAIL"

    # yum 기반 시스템 보안 패치 적용 여부 점검
    if command -v yum >/dev/null 2>&1; then
      PATCH_LIST=$(yum updateinfo list security available 2>/dev/null | sed '1,2d' | grep -v '^\s*$' | head -5)
      PATCH_COUNT=$(echo "$PATCH_LIST" | grep -c .)

      [[ "$PATCH_COUNT" -eq 0 ]] && PATCH_LIST="없음"

      APPLIED_FULL_LIST=$(yum updateinfo list security installed 2>/dev/null | sed '1,2d' | grep -v '^\s*$')
      APPLIED_PATCH_LIST=""
      APPLIED_PATCH_COUNT=0

      while IFS= read -r line; do
        PKG=$(echo "$line" | awk '{print $1}')
        INSTALL_DATE_STR=$(rpm -qi "$PKG" 2>/dev/null | grep "Install Date" | sed 's/Install Date *: //')
        if [ -n "$INSTALL_DATE_STR" ]; then
          INSTALL_DATE=$(date -d "$INSTALL_DATE_STR" +%s)
          if [ "$INSTALL_DATE" -ge "$DAYS_AGO_30" ]; then
            APPLIED_PATCH_LIST="${APPLIED_PATCH_LIST}${line}\n"
            ((APPLIED_PATCH_COUNT++))
          fi
        fi
      done <<< "$APPLIED_FULL_LIST"

      LAST_PATCH_DATE=$(rpm -qa --last 2>/dev/null | grep security | head -1 | awk '{print $1, $2, $3, $4}')
      [ -z "$LAST_PATCH_DATE" ] && LAST_PATCH_DATE="정보 없음"

      PATCH_APPLIED_STATUS="정기적"
      PATCH_APPLIED_DETAIL=$(cat <<EOF
적용 가능한 보안 패치 수: $PATCH_COUNT
적용 가능한 보안 패치 목록:
$(echo "$PATCH_LIST" | sed 's/^/  - /')
최근 30일간 적용된 보안 패치 수: $APPLIED_PATCH_COUNT
최근 적용된 보안 패치 목록:
$(echo -e "$APPLIED_PATCH_LIST" | sed 's/^/  - /')
마지막 보안 패치 설치 날짜: $LAST_PATCH_DATE
EOF
)
    else
      PATCH_APPLIED_STATUS="비정기적"
    fi

    echo "  - 패치 적용 상태 : $PATCH_APPLIED_STATUS"
    [ "$PATCH_APPLIED_STATUS" == "정기적" ] && echo "$PATCH_APPLIED_DETAIL"

    echo "------------------------------------------------------------------"

    # 결과 종합 판단
    if [ "$PATCH_POLICY_STATUS" == "설정됨" ] && [ "$PATCH_APPLIED_STATUS" == "정기적" ]; then
      STATUS="양호"
      RISK_LEVEL="저"
    elif [ "$PATCH_POLICY_STATUS" == "미설정" ] || [ "$PATCH_APPLIED_STATUS" == "비정기적" ]; then
      STATUS="취약"
      RISK_LEVEL="상"
    fi

    echo "최종 진단 결과     : $STATUS"
    echo "=================================================================="

    if [ "$STATUS" == "취약" ]; then
      echo "[취약 사유 상세 설명]"
      echo "- 최신 보안 패치가 정기적으로 적용되지 않았거나, 패치 정책이 설정되지 않음."
      echo "- 이는 취약점 공격에 노출될 수 있으며 시스템 침해 가능성을 증가시킵니다."
      echo ""
      echo "[조치 권고 사항]"
      echo "- 보안 패치 정책(/etc/yum.repos.d 또는 /etc/apt/sources.list)을 설정하고,"
      echo "- 주기적으로 보안 패치를 적용해야 합니다."
      echo "- 자동 패치 적용 설정 또는 주기적인 점검을 통해 최신 상태를 유지하십시오."
    fi
  } > "$LOG_FILE"
}

# <--------------------------- 로그 관리 ---------------------->
# [U-43] 로그 정기적 검토 및 보고
U43_REPORT="$LOG_DIR/U-43.txt"
U_43_STATUS="양호"

echo "[U-43] 로그 정기적 검토 및 보고 시작" > "$U43_REPORT"
echo "로그 분석 리포트" >> "$U43_REPORT"
echo "----------------------------" >> "$U43_REPORT"
echo "분석 시각: $(date)" >> "$U43_REPORT"
echo "----------------------------" >> "$U43_REPORT"

echo "[로그 파일] utmp, wtmp, btmp 파일 점검" >> "$U43_REPORT"

if [ -f /var/log/utmp ]; then
    echo "[utmp] 마지막 로그인 정보:" >> "$U43_REPORT"
    last -f /var/log/utmp | head -n 10 >> "$U43_REPORT"
else
    echo "/var/log/utmp 파일이 존재하지 않습니다. (취약)" >> "$U43_REPORT"
    U_43_STATUS="취약"
fi

if [ -f /var/log/wtmp ]; then
    echo "[wtmp] 로그인 기록:" >> "$U43_REPORT"
    last -f /var/log/wtmp | head -n 10 >> "$U43_REPORT"
else
    echo "/var/log/wtmp 파일이 존재하지 않습니다. (취약)" >> "$U43_REPORT"
    U_43_STATUS="취약"
fi

if [ -f /var/log/btmp ]; then
    echo "[btmp] 로그인 실패 기록:" >> "$U43_REPORT"
    lastb | head -n 10 >> "$U43_REPORT"
else
    echo "/var/log/btmp 파일이 존재하지 않습니다. (취약)" >> "$U43_REPORT"
    U_43_STATUS="취약"
fi

echo "[로그 파일] secure 파일 점검" >> "$U43_REPORT"
echo "[secure] su 명령어 로그:" >> "$U43_REPORT"

if [ -f /var/log/secure ]; then
    grep "su:" /var/log/secure | while read line; do
        [[ "$line" =~ "authentication failure" ]] && {
            echo "[su 명령어] 실패한 인증 시도" >> "$U43_REPORT"
            echo "$line" >> "$U43_REPORT"
            U_43_STATUS="취약"
        }
        [[ "$line" =~ "session opened" ]] && {
            echo "[su 명령어] 세션 열림" >> "$U43_REPORT"
            echo "$line" >> "$U43_REPORT"
            U_43_STATUS="취약"
        }
    done

    echo "[wheel 그룹 사용자 su 시도 점검]" >> "$U43_REPORT"
    for user in $WHEEL_GROUP_USERS; do
        grep "su:" /var/log/secure | grep "$user" | while read line; do
            [[ "$line" =~ "authentication failure" ]] && {
                echo "[$user] 인증 실패: $line" >> "$U43_REPORT"
                U_43_STATUS="취약"
            }
            [[ "$line" =~ "session opened" ]] && {
                echo "[$user] 세션 열림: $line" >> "$U43_REPORT"
                U_43_STATUS="취약"
            }
        done
    done
else
    echo "/var/log/secure 파일이 존재하지 않습니다. (취약)" >> "$U43_REPORT"
    U_43_STATUS="취약"
fi

echo "-------------------------------------------" >> "$U43_REPORT"
echo "[U-43] 최종 진단 결과: $U_43_STATUS" >> "$U43_REPORT"


# [U-72] 시스템 로깅 설정 점검
U72_REPORT="$LOG_DIR/U-72.txt"
U_72_STATUS="양호"

echo "[U-72] 시스템 로깅 설정 점검 시작" > "$U72_REPORT"

if [ -f "$RSYSLOG_CONF" ]; then
    echo "[U-72] $RSYSLOG_CONF 파일이 존재합니다." >> "$U72_REPORT"

    grep -qE "^\s*.*\.info;mail.none;authpriv.none;cron.none\s+/var/log/messages" "$RSYSLOG_CONF"
    [ $? -eq 0 ] && echo "[✔] /var/log/messages 설정됨" >> "$U72_REPORT" || {
        echo "[✖] /var/log/messages 미설정" >> "$U72_REPORT"
        U_72_STATUS="취약"
    }

    grep -qE "^\s*authpriv\.\*\s+/var/log/secure" "$RSYSLOG_CONF"
    [ $? -eq 0 ] && echo "[✔] /var/log/secure 설정됨" >> "$U72_REPORT" || {
        echo "[✖] /var/log/secure 미설정" >> "$U72_REPORT"
        U_72_STATUS="취약"
    }

    grep -qE "^\s*mail\.\*\s+/var/log/maillog" "$RSYSLOG_CONF"
    [ $? -eq 0 ] && echo "[✔] /var/log/maillog 설정됨" >> "$U72_REPORT" || {
        echo "[✖] /var/log/maillog 미설정" >> "$U72_REPORT"
        U_72_STATUS="취약"
    }

    grep -qE "^\s*cron\.\*\s+/var/log/cron" "$RSYSLOG_CONF"
    [ $? -eq 0 ] && echo "[✔] /var/log/cron 설정됨" >> "$U72_REPORT" || {
        echo "[✖] /var/log/cron 미설정" >> "$U72_REPORT"
        U_72_STATUS="취약"
    }

    grep -qE "^\s*\*\.alert\s+/dev/console" "$RSYSLOG_CONF"
    [ $? -eq 0 ] && echo "[✔] *.alert /dev/console 설정됨" >> "$U72_REPORT" || {
        echo "[✖] *.alert /dev/console 미설정" >> "$U72_REPORT"
        U_72_STATUS="취약"
    }

    grep -qE "^\s*\*\.emerg\s+\*" "$RSYSLOG_CONF"
    [ $? -eq 0 ] && echo "[✔] *.emerg * 설정됨" >> "$U72_REPORT" || {
        echo "[✖] *.emerg * 미설정" >> "$U72_REPORT"
        U_72_STATUS="취약"
    }

else
    echo "[✖] $RSYSLOG_CONF 파일 없음" >> "$U72_REPORT"
    U_72_STATUS="취약"
fi

echo "-------------------------------------------" >> "$U72_REPORT"
echo "[U-72] 최종 진단 결과: $U_72_STATUS" >> "$U72_REPORT"

# 모든 점검 실행
checks=(
    check_u06 check_u05 check_u07
    check_u08 check_u09 check_u10
    check_u11 check_u12 check_u13
    check_u14 check_u15 check_u16
    check_u17 check_u18 check_u42
    check_u55 check_u56 check_u57
    check_u58 check_u59 check_u71
    check_u41 check_u60 check_u61 
    check_u62 check_u63 check_u64 
    check_u65 check_u66 check_u67 
    check_u68 check_u69 check_u70 
    check_u01 check_u02 check_u03
    check_u04 check_u44 check_u45
    check_u46 check_u47 check_u48
    check_u49 check_u50 check_u51
    check_u52 check_u53 check_u54)

for check in "${checks[@]}"; do
    $check
done
