import subprocess
import os
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit,
    QPushButton, QMessageBox, QFileDialog, QComboBox
)

HELP_TEXT = """
🛠️ Git 자동 동기화 도우미

- 📁 폴더 선택: 로컬 작업 디렉터리를 지정합니다.
- 🔗 원격 저장소 URL: GitHub 등 원격 저장소의 주소를 입력합니다.
- 브랜치 선택: 원격 브랜치 목록에서 선택합니다.
- 커밋 메시지: 기본 메시지를 수정하거나 그대로 둡니다.

🔁 Push 실행:
  - 선택한 폴더에 Git 저장소가 없으면 자동으로 초기화하고
    원격 저장소와 연결합니다.
  - 지정된 브랜치로 커밋 후 push 합니다.

🔄 Pull 실행:
  - 원격 저장소에서 지정된 브랜치의 내용을 fetch + rebase 방식으로 가져옵니다.
"""

class GitSyncApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Git 자동 동기화")
        self.resize(400, 300)

        self.layout = QVBoxLayout()

        self.dir_label = QLabel("🔍 로컬 디렉터리 선택:")
        self.layout.addWidget(self.dir_label)

        self.dir_button = QPushButton("폴더 선택")
        self.dir_button.clicked.connect(self.select_folder)
        self.layout.addWidget(self.dir_button)

        self.url_label = QLabel("🔗 원격 저장소 URL:")
        self.layout.addWidget(self.url_label)

        self.remote_input = QLineEdit()
        self.remote_input.textChanged.connect(self.load_remote_branches)
        self.layout.addWidget(self.remote_input)

        self.branch_label = QLabel("브랜치 선택:")
        self.layout.addWidget(self.branch_label)

        self.branch_combo = QComboBox()
        self.layout.addWidget(self.branch_combo)

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
            self.load_remote_branches()

    def run_git(self, command):
        result = subprocess.run(command, cwd=self.target_dir, shell=True, capture_output=True, text=True, encoding='utf-8')
        if result.stdout:
            print(result.stdout.strip())
        if result.stderr:
            print(result.stderr.strip())
        return result.stdout.strip()

    def load_remote_branches(self):
        if not self.target_dir or not self.remote_input.text():
            return

        remote_url = self.remote_input.text().strip()
        if not os.path.exists(os.path.join(self.target_dir, ".git")):
            self.run_git("git init")

        self.run_git("git remote remove origin")
        self.run_git(f"git remote add origin {remote_url}")
        self.run_git("git fetch --all")

        result = self.run_git("git branch -r")
        remote_branches = []
        seen = set()

        for line in result.splitlines():
            line = line.strip()
            if line.startswith("origin/") and "->" not in line:
                branch = line.replace("origin/", "")
                if branch not in seen:
                    seen.add(branch)
                    remote_branches.append(branch)

        self.branch_combo.clear()
        self.branch_combo.addItems(remote_branches)

    def auto_sync(self, action):
        if not self.remote_input.text() or not self.target_dir:
            QMessageBox.warning(self, "입력 오류", "저장소 URL과 디렉터리를 모두 입력하세요.")
            return

        remote_url = self.remote_input.text()
        branch = self.branch_combo.currentText() or "main"
        commit_message = self.commit_input.text() or "🔄 자동 푸시 및 동기화"

        try:
            if not os.path.exists(os.path.join(self.target_dir, ".git")):
                self.run_git("git init")
                self.run_git(f"git remote add origin {remote_url}")

            self.run_git(f"git checkout -B {branch}")
            self.run_git(f"git branch --set-upstream-to=origin/{branch} {branch}")
            self.run_git("git add -A")
            self.run_git(f'git commit -m "{commit_message}"')

            if action == 'push':
                self.run_git(f"git push --set-upstream origin {branch}")
            elif action == 'pull':
                self.run_git("git fetch origin")
                self.run_git(f"git rebase origin/{branch}")

            QMessageBox.information(self, "완료", f"{action.upper()} 성공!")
        except Exception as e:
            QMessageBox.critical(self, "오류 발생", str(e))

    def clone_repo(self):
        if not self.remote_input.text() or not self.target_dir:
            QMessageBox.warning(self, "입력 오류", "저장소 URL과 디렉터리를 모두 입력하세요.")
            return

        remote_url = self.remote_input.text()

        try:
            if not os.path.exists(self.target_dir):
                os.makedirs(self.target_dir)

            self.run_git(f"git clone {remote_url}")
            QMessageBox.information(self, "완료", "Git 저장소 클론 성공!")
        except Exception as e:
            QMessageBox.critical(self, "오류 발생", str(e))

    def show_help(self):
        QMessageBox.information(self, "도움말", HELP_TEXT)


if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    window = GitSyncApp()
    window.show()
    sys.exit(app.exec_())
