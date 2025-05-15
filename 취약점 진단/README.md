# 5. 로그 관리

## 5.1 로그의 정기적 검토 및 보고

### 취약점 개요

| 점검내용 | 로그의 정기적 검토 및 보고 여부 점검 |
| --- | --- |
| 점검목적 | 정기적인 로그 점검을 통해 안정적인 시스템 상태 유지 및 외부 공격 여부를 파악하기 위함 |
| 보안위협 | 로그의 검토 및 보고 절차가 없는 경우 외부 침입 시도에 대한 식별이 누락될 수 있고, 침입 시도가 의심되는 사례 발견 시 관련 자료를 분석하여 해당장비에 대한 접근을 차단하는 등의 추가 조치가 어려움 |

### 판단 기준

| 양호 | 접속기록 등의 보안 로그, 응용 프로그램 및 시스템 로그 기록에 대해 정기적으로 검토, 분석, 리포트 작성 및 보고 등의 조치가 이루어지는 경우 |
| --- | --- |
| 취약 | 위 로그 기록에 대해 정기적으로 검토, 분석, 리포트 작성 및 보고 등의 조치가 이루어 지지 않는 경우 |
| 조치 방법 | 로그 기록 검토 및 분석을 시행하여 리포트를 작성하고 정기적으로 보고함 |

### 진단

### 주기적인 로그 분석 계획 및 정책이 수립되어 있는지 확인

```bash
ls -l /etc/cron.daily/
# 정기 실행되는 로그 관련 스크립트 확인
```

![image.png](image.png)

```bash
ls -l /etc/cron.weekly/
```

![image.png](image%201.png)

```bash
cat /etc/crontab
```

![image.png](image%202.png)

```bash
ls -l /etc/logrotate.d/
# logrotate 설정 확인
```

![image.png](image%203.png)

```bash
ls /etc/logrotate.d/
```

![image.png](image%204.png)

### 2. 로그 파일 점검 항목

### 📌 **utmp, wtmp, btmp 로그**

- 로그인 및 실패한 로그인 시도 내역 확인

```bash
# 현재 로그인 사용자 확인
who

# 과거 로그인 기록
last

# 실패한 로그인 시도 기록
lastb  # /var/log/btmp 파일 기반
```

![image.png](image%205.png)

![image.png](image%206.png)

```bash
lastblog  # 마지막으로 성공한 로그인 정보를 담고있는 로그파일
# var/log/lastlog
```

![image.png](image%207.png)

---

## 📌 b. **sulog (su 명령 기록)**

su 명령어 사용 기록 확인: `/var/log/secure`

```bash
grep 'su:' /var/log/secure
```

![image.png](image%208.png)

`su` 명령 시도 내역을 통해 권한 상승 시도를 추적 가능

## 🔹 **1. 성공적인 권한 상승**

```
May 14 02:25:49 localhost su: pam_unix(su-l:session): session opened for user root by wins(uid=1000)
```

- **일반 사용자 `wins`가 `su -` 명령어를 이용해 root 계정으로 전환했고, 성공함**
- `uid=1000`은 일반 사용자임
- → **✅ 권한 상승 성공**

---

## 🔹 **2. 권한 상승 실패 (인증 실패)**

```
May 14 07:40:12 localhost su: pam_unix(su-l:auth): authentication failure; logname=wins uid=1000 euid=0 tty=pts/0 ruser=wins rhost=  user=root
```

- `wins` 사용자가 root로 전환을 시도했으나 **비밀번호가 틀려서 실패**
- → **❌ 권한 상승 시도 실패 (인증 실패)**

---

## 🔹 **3. 정책 조건 불충족 (root 사용자는 허용 안 됨)**

```
May 14 07:40:12 localhost su: pam_succeed_if(su-l:auth): requirement "uid >= 1000" not met by user "root"
```

- 정책(pam 설정 등)에 따라 **uid 1000 이상(즉, 일반 사용자)만 허용**되도록 되어 있는데
- `root(uid=0)`은 이 조건을 만족하지 않아 **정책 차단**

> 이건 추가적인 정책 설정에 의한 실패 메시지이며, 위의 실패와 같이 봐야 합니다.
> 

---

## 🔹 **4. 다시 권한 상승 성공**

```
May 14 07:40:22 localhost su: pam_unix(su-l:session): session opened for user root by wins(uid=1000)
```

- 위 실패 후 다시 시도했고, 이번에는 성공함
- → **✅ 권한 상승 성공**

---

## 🔹 **5. root 계정이 su 실행 (즉, root → root)**

```
May 14 13:27:23 localhost su: pam_unix(su:session): session opened for user root by root(uid=0)
```

- root가 su 명령어로 다시 root로 로그인
- 큰 의미는 없지만 **root 계정 사용 흔적**으로는 중요함
- → **⚠ 관리자 직접 접근 확인용**

---

## 🔎 정리: 무엇을 의미하나?

| 시간 | 사용자 | 결과 | 설명 |
| --- | --- | --- | --- |
| 02:25 | wins → root | ✅ 성공 | 권한 상승 성공 |
| 07:40 | wins → root | ❌ 실패 | 비밀번호 실패 |
| 07:40 | wins → root | ✅ 성공 | 다시 시도하여 성공 |
| 13:27 | root → root | ⚠ 무해 | root 계정의 su 실행 (무시 가능) |

---

## 🚨 주의해야 할 포인트

- `wins` 계정이 **반복적으로 root 권한을 시도하고 있음**
- 실패 후 재시도하여 결국 성공 → **의도된 접근인지 확인 필요**
- 비정상 시간이거나 불필요한 root 접근이라면 **정책 검토 또는 로그 주시 필요**

---

## 📌 c. **xferlog (FTP 로그)**

- FTP 서비스 사용 시 전송 기록 확인: `/var/log/xferlog`

<aside>
❓

xferlog 파일이 없음 → FTP가 활성화 되지 않은거 같음

</aside>

![image.png](image%209.png)

---

## 📌 d. **기타 중요 로그**

- 시스템 보안 및 이상 징후 탐지를 위한 주요 로그

```bash
cat /var/log/messages |egrep -i "critical|error|warn|alert|fault|fail"
# 파일 경로 /var/log/messages
```

![image.png](image%2010.png)

![image.png](image%2011.png)

```bash
cat /var/log/secure |egrep -i "critical|error|warn|alert|fault|fail"
# 파일 경로 /var/log/secure
```

![image.png](image%2012.png)

```bash
cat /var/log/maillog |egrep -i "critical|error|warn|alert|fault|fail"
```

![image.png](image%2013.png)

<aside>
❓

결과값 없음

</aside>

```bash
cat /var/log/httpd/access_log |egrep -i "critical|error|warn|alert|fault|fail"
```

![image.png](image%2014.png)

<aside>
❓

결과값 없음 

</aside>

### 조치 방법

<aside>
❗

로그 분석에 대한 결과 보고서 작성

로그 분석 결과보고서 보고 체계 수립

</aside>

### 판단

<aside>
❗

접속기록 등의 보안 로그, 응용 프로그램 및 시스템 로그 기록에 대해 정기적으로 검토, 분석, 리포트 작성 및 보고 등의 조치가 이루워 지지 않음

</aside>

## 5.2 정책에 따른 시스템 로깅 설정

### 취약점 개요

| 점검내용 | 내부 정책에 따른 시스템 로깅 설정 적용 여부 점검 |
| --- | --- |
| 점검목적 | 보안 사고 발생 시 원인 파악 및 각종 침해 사실에 대한 확인을 하기 위함 |
| 보안위협 | 로깅 설정이 되어 있지 않을 경우 원인 규명이 어려우며, 법적 대응을 위한충분한 증거로 사용할 수 없음 |

### 판단 기준

| 양호 | 로그 기록 정책이 정책에 따라 설정되어 수립되어 있으며 보안정책에 따라 로그를 남기고 있을 경우 |
| --- | --- |
| 취약 | 로그 기록 정책 미수립 또는, 정책에 따라 설정되어 있지 않거나 보안정책에 따라 로그를 남기고 있지 않을 경우 |
| 조치방법 | 로그 기록 정책을 수립하고, 정책에 따라 syslog.conf 파일을 설정 |

### 점검

vi 편집기를 이용하여 “/etc/rsyslog.conf” 파일 열기

```bash
vi /etc/rsyslog.conf
```

## **Rules**

<aside>
💡

기존 파일

</aside>

![image.png](image%2015.png)

### 판단

<aside>
❗

로그 기록 정책 미수립 또는, 정책에 따라 설정되어 있지 않거나 보안정
책에 따라 로그를 남기고 있지 않음으로 취약하다 판단

</aside>

### 조치 방법

 vi 편집기를 이용하여 “/etc/syslog.conf” 파일 열기

```bash
vi /etc/syslog.conf
```

아래와 같이 수정 또는, 신규 삽입

![image.png](image%2016.png)

설정 후 SYSLOG 데몬 재시작

```bash
#ps –ef | grep syslogd
 root 7524 6970 0 Apr 23 - 0:02 /usr/sbin/syslogd
#kill –HUP [PID]
```

---
