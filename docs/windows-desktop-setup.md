\# SecureSphere AI — Windows Desktop Setup



\## 1. Overview



SecureSphere AI includes a desktop watcher that monitors the current user's

Downloads folder for newly appearing files with selected extensions.



\- APK files use the SecureSphere backend when authentication is configured.

\- Without backend authentication, APK files use the local APK scanner.

\- EXE, MSI, ZIP, JAR, BAT, CMD, PS1 and SCR files are scanned with Windows Defender.

\- Unavailable or inconclusive scan results are reported as Unverified.



The watcher reports scan results. It does not itself block downloads, quarantine

files, or guarantee that a file is safe.



\## 2. Requirements



\- Windows with Windows Defender available and enabled.

\- Python installed and accessible through the `python` command.

\- SecureSphere AI repository cloned to your computer.

\- Project dependencies installed.

\- A configured application environment and database for backend scanning.



Run the following commands from the repository root:



```cmd

python -m pip install -r requirements.txt -r backend\\requirements.txt
