
[U-43] 로그 정기적 검토 및 보고 시작
로그 분석 리포트
----------------------------
분석 시각: 2025. 05. 15. (목) 05:53:15 KST
----------------------------
[로그 파일] utmp, wtmp, btmp 파일 점검
/var/log/utmp 파일이 존재하지 않습니다. (취약)
[wtmp] 로그인 기록:
root     pts/1        10.0.2.2         Thu May 15 02:48   still logged in
root     pts/0        10.0.2.2         Thu May 15 02:46   still logged in
root     pts/0        10.0.2.2         Thu May 15 02:41 - 02:42  (00:01)
root     pts/0        10.0.2.2         Wed May 14 17:20 - 02:40  (09:19)
root     pts/0        10.0.2.2         Wed May 14 14:02 - 17:19  (03:17)
root     pts/0        10.0.2.2         Wed May 14 10:54 - 13:41  (02:46)
root     tty1                          Wed May 14 10:29   still logged in
reboot   system boot  3.10.0-327.36.1. Wed May 14 10:28 - 05:53  (19:24)
wins     pts/0        10.0.2.2         Wed May 14 07:40 - 07:45  (00:05)
reboot   system boot  3.10.0-327.36.1. Wed May 14 07:39 - 07:45  (00:05)
[btmp] 로그인 실패 기록:
root     tty1                          Wed May 14 10:29 - 10:29  (00:00)
root     pts/0                         Wed May 14 07:40 - 07:40  (00:00)
root     pts/0                         Wed May 14 03:15 - 03:15  (00:00)

btmp begins Wed May 14 03:15:41 2025
[로그 파일] secure 파일 점검
[secure] su 명령어 로그:
[su 명령어] 권한 상승 시도 있음: 세션 열린 로그
May 14 02:25:49 localhost su: pam_unix(su-l:session): session opened for user root by wins(uid=1000)
[su 명령어] 권한 상승 시도 있음: 실패한 인증
May 14 07:40:12 localhost su: pam_unix(su-l:auth): authentication failure; logname=wins uid=1000 euid=0 tty=pts/0 ruser=wins rhost=  user=root
[su 명령어] 권한 상승 시도 있음: 세션 열린 로그
May 14 07:40:22 localhost su: pam_unix(su-l:session): session opened for user root by wins(uid=1000)
[su 명령어] 권한 상승 시도 있음: 세션 열린 로그
May 14 13:27:23 localhost su: pam_unix(su:session): session opened for user root by root(uid=0)
[로그 파일] su 명령어 권한 상승 시도 및 wheel 그룹 사용자 점검
[U-72] 시스템 로깅 설정 점검 시작
[U-72] /etc/rsyslog.conf 파일이 존재합니다.
[U-72] /var/log/messages 로그 정책이 설정되어 있습니다. (양호)
[U-72] /var/log/secure 로그 정책이 설정되어 있습니다. (양호)
[U-72] /var/log/maillog 로그 정책 설정이 없습니다. (취약)
[U-72] /var/log/cron 로그 정책이 설정되어 있습니다. (양호)
[U-72] *.alert /dev/console 설정이 없습니다. (취약)
[U-72] *.emerg * 설정이 없습니다. (취약)
-------------------------------------------
최종 진단 결과
[U-43] 로그 정기적 검토 및 보고 결과: 취약
[U-72] 시스템 로깅 설정 점검 결과: 취약
