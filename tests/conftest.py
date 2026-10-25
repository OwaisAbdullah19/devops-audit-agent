import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

WORKFLOW = """name: CI
on:
  pull_request_target:
  push:
    branches: [develop]
permissions: write-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: someone/custom-action@main
      - name: tests
        run: pytest
        continue-on-error: true
      - run: echo "${{ github.event.pull_request.title }}"
"""


def _git(root, *args):
    subprocess.run(["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@t", *args],
                   check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "demo"
    (root / ".github/workflows").mkdir(parents=True)
    (root / "src").mkdir()
    (root / "README.md").write_text("# demo\n")
    (root / ".gitignore").write_text("*.log\n__pycache__/\n")
    (root / "config.py").write_text(
        'import os\nDB = os.environ["DB_URL"]\nAPI_KEY = "sk-abcdefghijklmnopqrstuvwxyz123456"\n'
        'password = "hunter2hunter2"\nPATH = "/home/alice/data"\n')
    (root / "src/app.py").write_text("def f():\n    return 1\n")
    (root / "debug.log").write_text("noise\n")
    (root / "image.bin").write_bytes(b"\x00\x01\x02binary")
    (root / ".github/workflows/ci.yml").write_text(WORKFLOW)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    _git(root, "add", "-f", ".")
    _git(root, "commit", "-q", "-m", "init with token ghp_" + "a" * 36)
    return root
