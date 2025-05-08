import subprocess
import os
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit,
    QPushButton, QMessageBox, QFileDialog
)

HELP_TEXT = """
🛠️ Git 자동 동기화 도우미

- 📁 폴더 선택: 로컬 작업 디렉터리를 지정합니다.
- 🔗 원격 저장소 URL: GitHub 등 원격 저장소의 주소를 입력합니다.
- 브랜치 (기본: main): 작업할 브랜치를 입력하거나 그대로 둡니다.
- 커밋 메시지: 기본 메시지를 수정하거나 그대로 둡니다.

🔁 Push 실행:
  - 선택한 폴더에 Git 저장소가 없으면 자동으로 초기화하고
    원격 저장소와 연결합니다.
  - 지정된 브랜치로 커밋 후 push 합니다.

🔄 Pull 실행:
  - 원격 저장소에서 지정된 브랜치의 내용을 fetch + rebase 방식으로 가져옵니다.

📌 저장소 권한 안내:
- 이 프로그램은 본인이 소유하거나, **push 권한이 있는 저장소**에서만 push할 수 있습니다.
- 다른 사람의 **공개 저장소(public repo)**에 대해서는 **pull은 가능**하지만 push는 불가능합니다.
- 원격 저장소가 인증(HTTPS + 토큰, SSH 등)을 요구할 경우, 별도 인증이 필요합니다.

💡 참고:
- 선택한 폴더는 지정한 원격 저장소와 연결됩니다.
- 이미 연결된 폴더는 다른 원격 저장소로 변경할 수 없습니다.
- GUI에서는 ❓ 도움말 보기 버튼을 눌러 이 도움말을 다시 확인할 수 있습니다.
"""

class GitSyncApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Git 자동 동기화")
        self.resize(400, 250)

        self.layout = QVBoxLayout()

        self.dir_label = QLabel("🔍 로컬 디렉터리 선택:")
        self.layout.addWidget(self.dir_label)

        self.dir_button = QPushButton("폴더 선택")
        self.dir_button.clicked.connect(self.select_folder)
        self.layout.addWidget(self.dir_button)

        self.url_label = QLabel("🔗 원격 저장소 URL:")
        self.layout.addWidget(self.url_label)

        self.remote_input = QLineEdit()
        self.layout.addWidget(self.remote_input)

        self.branch_label = QLabel("브랜치 (기본: main):")
        self.layout.addWidget(self.branch_label)

        self.branch_input = QLineEdit("main")
        self.layout.addWidget(self.branch_input)

        self.commit_label = QLabel("커밋 메시지:")
        self.layout.addWidget(self.commit_label)

        self.commit_input = QLineEdit("🔄 자동 푸시 및 동기화")
        self.layout.addWidget(self.commit_input)

        self.push_button = QPushButton("Push 실행")
        self.push_button.clicked.connect(lambda: self.auto_sync('push'))
        self.layout.addWidget(self.push_button)

        self.pull_button = QPushButton("Pull 실행")
        self.pull_button.clicked.connect(lambda: self.auto_sync('pull'))
        self.layout.addWidget(self.pull_button)

        self.clone_button = QPushButton("Clone 실행")
        self.clone_button.clicked.connect(self.clone_repo)
        self.layout.addWidget(self.clone_button)

        # 추가된 물음표 버튼
        self.help_button = QPushButton("❓ 도움말")
        self.help_button.clicked.connect(self.show_help)
        self.layout.addWidget(self.help_button)

        self.setLayout(self.layout)
        self.target_dir = ""

    def select_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "디렉터리 선택")
        if folder:
            self.target_dir = folder
            self.dir_label.setText(f"📁 선택된 폴더: {folder}")

    def run_git(self, command):
        result = subprocess.run(command, cwd=self.target_dir, shell=True, capture_output=True, text=True, encoding='utf-8')
        if result.stdout:
            print(result.stdout.strip())
        if result.stderr:
            print(result.stderr.strip())

    def auto_sync(self, action):
        if not self.remote_input.text() or not self.target_dir:
            QMessageBox.warning(self, "입력 오류", "저장소 URL과 디렉터리를 모두 입력하세요.")
            return

        remote_url = self.remote_input.text()
        branch = self.branch_input.text() or "main"  # 기본 브랜치는 main
        commit_message = self.commit_input.text() or "🔄 자동 푸시 및 동기화"  # 기본 커밋 메시지

        try:
            # Git 저장소 초기화 및 원격 저장소 추가
            if not os.path.exists(os.path.join(self.target_dir, ".git")):
                self.run_git("git init")
                self.run_git(f"git remote add origin {remote_url}")

            # 브랜치 확인 후 생성 또는 체크아웃
            self.run_git(f"git checkout -B {branch}")  # 브랜치가 없으면 생성
            self.run_git(f"git branch --set-upstream-to=origin/{branch} {branch}")

            # 삭제된 파일 처리: 삭제된 파일을 Git에서 추적하도록 처리
            self.run_git("git add -A")  # 삭제된 파일 포함 모든 변경 사항 추가
            self.run_git(f'git commit -m "{commit_message}"')  # 커밋

            if action == 'push':
                self.run_git(f"git push --set-upstream origin {branch}")
            elif action == 'pull':
                # pull 전에 로컬 커밋이 없으면 먼저 커밋을 진행
                self.run_git("git fetch origin")
                self.run_git(f"git rebase origin/{branch}")
                self.run_git(f"git pull origin {branch}")

            QMessageBox.information(self, "완료", f"{action.upper()} 성공!")
        except Exception as e:
            QMessageBox.critical(self, "오류 발생", str(e))

    def clone_repo(self):
        if not self.remote_input.text() or not self.target_dir:
            QMessageBox.warning(self, "입력 오류", "저장소 URL과 디렉터리를 모두 입력하세요.")
            return

        remote_url = self.remote_input.text()

        try:
            # Git 클론 실행
            if not os.path.exists(self.target_dir):
                os.makedirs(self.target_dir)

            # git clone 실행 시 경로를 cwd로 설정
            self.run_git(f"git clone {remote_url}")  # target_dir을 cwd로 설정하여 클론

            QMessageBox.information(self, "완료", "Git 저장소 클론 성공!")
        except Exception as e:
            QMessageBox.critical(self, "오류 발생", str(e))

    def show_help(self):
        # 도움말 내용 표시
        QMessageBox.information(self, "도움말", HELP_TEXT)


if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    window = GitSyncApp()
    window.show()
    sys.exit(app.exec_())
