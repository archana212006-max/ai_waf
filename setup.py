#!/usr/bin/env python3
"""
AI-Powered WAF - One-click setup script
Run: python setup.py
"""

import subprocess
import sys
import os
from pathlib import Path


def run(cmd, check=True):
    print(f"  $ {cmd}")
    result = subprocess.run(cmd, shell=True, check=check)
    return result.returncode == 0


def main():
    print("\n" + "="*55)
    print("   🛡️  AI-Powered Web Application Firewall — Setup")
    print("="*55 + "\n")

    # 1. Check Python version
    if sys.version_info < (3, 9):
        print("❌ Python 3.9+ required. Current:", sys.version)
        sys.exit(1)
    print(f"✅ Python {sys.version.split()[0]} detected\n")

    # 2. Create virtual environment
    venv_path = Path("venv")
    if not venv_path.exists():
        print("📦 Creating virtual environment...")
        run(f"{sys.executable} -m venv venv")
        print("✅ Virtual environment created\n")
    else:
        print("✅ Virtual environment already exists\n")

    # 3. Determine pip path
    if os.name == "nt":
        pip = "venv\\Scripts\\pip"
        python = "venv\\Scripts\\python"
        activate = "venv\\Scripts\\activate"
    else:
        pip = "venv/bin/pip"
        python = "venv/bin/python"
        activate = "source venv/bin/activate"

    # 4. Install dependencies
    print("📥 Installing dependencies...")
    run(f"{pip} install --upgrade pip -q")
    run(f"{pip} install -r requirements.txt -q")
    print("✅ Dependencies installed\n")

    # 5. Create directories
    print("📁 Creating directories...")
    for d in ["logs", "static/css", "static/js", "templates"]:
        Path(d).mkdir(parents=True, exist_ok=True)
    print("✅ Directories ready\n")

    # 6. Copy .env
    if not Path(".env").exists() and Path(".env.example").exists():
        import shutil
        shutil.copy(".env.example", ".env")
        print("📝 .env created from .env.example\n")

    # 7. Run tests
    print("🧪 Running test suite...")
    test_result = run(f"{python} -m pytest tests/ -v --tb=short", check=False)
    if test_result:
        print("✅ All tests passed\n")
    else:
        print("⚠️  Some tests failed (check output above)\n")

    # 8. Done
    print("="*55)
    print("   🚀 Setup Complete!")
    print("="*55)
    print(f"""
Next steps:
  1. Activate venv:  {activate}
  2. Edit .env:      Set WAF_TARGET to your backend URL
  3. Start WAF:      python main.py

  WAF Dashboard →   http://localhost:8000
  API Docs      →   http://localhost:8000/api/docs
  
  Protects against: SQLi, XSS, CSRF, Path Traversal,
                    Command Injection, Scanners & Bots
""")


if __name__ == "__main__":
    main()
