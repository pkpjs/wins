---

## 자동화 스크립트

### ▶️ 5.1 로그 점검 자동화 스크립트

```bash
#!/bin/bash

output="read.txt"
echo "=== 주요 로그인 및 인증 로그 파일 존재 여부 및 로그 내용 확인 ===" > "$output"

declare -A files=(
    [utmp]="/var/run/utmp"
    [wtmp]="/var/log/wtmp"
    [btmp]="/var/log/btmp"
    [sulog]="/var/log/secure"
    [xferlog]="/var/log/xferlog"
)

for name in "${!files[@]}"; do
    path="${files[$name]}"
    if [ -f "$path" ]; then
        echo -e "\n[+] $name 파일 존재: $path" >> "$output"

        case "$name" in
            utmp)
                echo ">> 현재 로그인 사용자 목록 (who 명령 결과):" >> "$output"
                who >> "$output"
                ;;
            wtmp)
                echo ">> 로그인/로그아웃 기록 (last -n 5):" >> "$output"
                last -n 5 >> "$output"
                ;;
            btmp)
                echo ">> 로그인 실패 기록 (lastb -n 5):" >> "$output"
                lastb -n 5 >> "$output"
                ;;
            sulog|xferlog)
                echo ">> 마지막 5줄:" >> "$output"
                tail -n 5 "$path" >> "$output"
                ;;
        esac
    else
        echo -e "\n[-] $name 파일 없음: $path" >> "$output"
    fi
done

echo -e "\n=== 설명 ===" >> "$output"
echo "utmp   : 현재 로그인한 사용자 정보" >> "$output"
echo "wtmp   : 로그인/로그아웃 기록 (last 명령어용)" >> "$output"
echo "btmp   : 로그인 실패 기록 (lastb 명령어용)" >> "$output"
echo "sulog  : su 명령어 사용 내역 (없을 수도 있음)" >> "$output"
echo "xferlog: FTP 전송 기록 (FTP 서비스 설정 시 생성)" >> "$output"

echo -e "\n보고서가 'read.txt'에 저장되었습니다."
```

---
