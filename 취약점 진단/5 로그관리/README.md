# 5. 로그 관리

## 5.1 로그의 정기적 검토 및 보고

### 취약점 개요

| 점검 내용 | 로그의 정기적 검토 및 보고 여부 점검                        |
| ----- | -------------------------------------------- |
| 점검 목적 | 정기적인 로그 점검을 통해 안정적인 시스템 상태 유지 및 외부 공격 여부 파악  |
| 보안 위협 | 로그 검토 및 보고 절차 부재 시 외부 침입 시도 식별 누락, 추가 조치 어려움 |

### 판단 기준

| 상태    | 설명                                                                     |
| ----- | ---------------------------------------------------------------------- |
| 양호    | 접속 기록, 보안 로그, 응용 프로그램 및 시스템 로그에 대해 정기적으로 검토, 분석, 리포트 작성 및 보고가 이루어지는 경우 |
| 취약    | 로그 기록에 대해 정기 검토, 분석, 리포트 작성 및 보고가 이루어지지 않는 경우                          |
| 조치 방법 | 로그 기록 검토 및 분석 시행 후 리포트 작성 및 정기 보고                                      |

### 점검 내용

#### 1) 주기적 로그 분석 계획 및 정책 확인

```bash
ls -l /etc/cron.daily/   # 일간 로그 관련 스크립트 확인
ls -l /etc/cron.weekly/  # 주간 로그 관련 스크립트 확인
cat /etc/crontab         # 시스템 cron 설정 확인
ls -l /etc/logrotate.d/  # 로그 순환 설정 확인
```

#### 2) 주요 로그 파일 점검

* **utmp, wtmp, btmp** (로그인/로그아웃 및 실패한 로그인 내역)

```bash
who       # 현재 로그인 사용자
last      # 과거 로그인 기록
lastb     # 실패한 로그인 시도 (/var/log/btmp 기반)
lastlog   # 마지막 로그인 정보 (/var/log/lastlog)
```

* **sulog (su 명령 기록)**

```bash
grep 'su:' /var/log/secure
```

* 권한 상승 성공 및 실패 기록을 확인하여 비정상 접근 시도 여부 점검

| 메시지 예시                                             | 설명                             |
| -------------------------------------------------- | ------------------------------ |
| `session opened for user root by wins(uid=1000)`   | wins 사용자가 su로 root 권한 획득 성공    |
| `authentication failure`                           | su 권한 상승 시도 중 비밀번호 실패          |
| `requirement "uid >= 1000" not met by user "root"` | 정책에 따른 권한 상승 실패 (root 계정 제한 등) |
| `session opened for user root by root(uid=0)`      | root 계정이 직접 su 실행              |

* **xferlog (FTP 로그)**

```bash
ls /var/log/xferlog
```

* FTP 사용 여부 및 전송 기록 확인

* **기타 중요 로그**

```bash
cat /var/log/messages | egrep -i "critical|error|warn|alert|fault|fail"
cat /var/log/secure | egrep -i "critical|error|warn|alert|fault|fail"
cat /var/log/maillog | egrep -i "critical|error|warn|alert|fault|fail"
cat /var/log/httpd/access_log | egrep -i "critical|error|warn|alert|fault|fail"
```

### 진단 및 조치 권고

* 로그 분석 결과 보고서 작성 및 정기 보고 체계 수립
* 비정상 권한 상승 시도, 반복 실패 등 의심 징후 발견 시 추가 정책 검토 및 모니터링 강화 필요

---

## 5.2 정책에 따른 시스템 로깅 설정

### 취약점 개요

| 점검 내용 | 내부 정책에 따른 시스템 로깅 설정 적용 여부 점검    |
| ----- | ------------------------------- |
| 점검 목적 | 보안 사고 시 원인 파악 및 침해 사실 확인을 위해 필수 |
| 보안 위협 | 로깅 설정 부재 시 원인 규명 및 법적 증거 확보 불가  |

### 판단 기준

| 상태 | 설명                         |
| -- | -------------------------- |
| 양호 | 로그 기록 정책 수립 및 정책에 따라 로그 남김 |
| 취약 | 정책 미수립, 설정 미흡 또는 정책 미준수 상태 |

### 점검 방법

* `/etc/rsyslog.conf` 또는 `/etc/syslog.conf` 파일 내용 확인

```bash
vi /etc/rsyslog.conf
```

* 필요한 로그 항목이 정책에 맞게 설정되어 있는지 확인

### 조치 방법

* `/etc/syslog.conf` 파일에 정책에 맞는 로그 기록 규칙 추가 또는 수정

* 예시

```
*.info;mail.none;authpriv.none;cron.none                /var/log/messages
authpriv.*                                              /var/log/secure
mail.*                                                  -/var/log/maillog
cron.*                                                  /var/log/cron
*.emerg                                                 *
uucp,news.crit                                         /var/log/spooler
local7.*                                                /var/log/boot.log
```

* SYSLOG 데몬 재시작

```bash
ps -ef | grep syslogd
kill -HUP [SYSLOG_PID]
```

---

### 자동화 스크립트 및 결과값
[자동화 스크립트](https://github.com/pkpjs/wins/blob/main/%EC%B7%A8%EC%95%BD%EC%A0%90%20%EC%A7%84%EB%8B%A8/5%20%EB%A1%9C%EA%B7%B8%EA%B4%80%EB%A6%AC/%EC%9E%90%EB%8F%99%ED%99%94%20%EC%8A%A4%ED%81%AC%EB%A6%BD%ED%8A%B8/5.sh)

[자동화 스크립트 결과값](https://github.com/pkpjs/wins/blob/main/%EC%B7%A8%EC%95%BD%EC%A0%90%20%EC%A7%84%EB%8B%A8/5%20%EB%A1%9C%EA%B7%B8%EA%B4%80%EB%A6%AC/%EC%9E%90%EB%8F%99%ED%99%94%20%EC%8A%A4%ED%81%AC%EB%A6%BD%ED%8A%B8/%EC%9E%90%EB%8F%99%ED%99%94%20%EA%B2%B0%EA%B3%BC%EA%B0%92.txt)

