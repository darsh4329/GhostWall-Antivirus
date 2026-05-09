# GhostWall-Antivirus
A Python‑based antivirus toolkit with malware scanner, file encryption, firewall, USB protection, system cleaner, lockdown, patch monitor, and password vault.

A lightweight, portable, and feature‑rich security suite for Windows – built with Python and Tkinter.

GhostWall combines essential security tools into one application: malware scanner (hash‑based), file locker (AES‑256), real‑time firewall, USB auto‑scanner, system cleaner, lockdown mode, patch monitor, and a password vault.

<img width="1920" height="1080" alt="Screenshot (189)" src="https://github.com/user-attachments/assets/cc58a88a-eb88-4cec-98fc-efa1b3bad50f" />


# 📌 Table of Contents
Problem
Solution
Features
Code Architecture & Details
Requirements
Installation
Running GhostWall
Configuration & Paths
Important Notes
License

# 🔥 Problem
Modern antivirus solutions are often heavy, resource‑intensive, and require constant internet connectivity. Many users need a portable, offline‑capable security toolkit that can:
Scan files/folders for known malware (SHA‑256 signatures)
Encrypt sensitive files locally
Block suspicious background processes (no visible window)
Automatically scan USB drives when inserted
Clean temporary junk files
Temporarily lock the system (e.g., for presentations or leaving a PC)
Check Windows update status
Store passwords securely
Existing tools may be closed‑source, expensive, or don’t combine all these features in one simple application.

# 🚀 Solution
GhostWall solves this by providing a single‑file, no‑install Python application with a modern dark‑theme GUI. All data (signatures, quarantine, logs, password vault) is stored in a self‑contained folder (GhostWall_Data) next to the script – making it fully portable.
Key design principles:
Offline first – signatures are local text files (SHA‑256 hashes).
Minimal dependencies – only a few Python libraries.
User‑controlled – no cloud, no telemetry.
Cross‑version compatible – works on Windows 10/11 (Python 3.8+).

# ✨ Features
Feature	Description
Malware Scanner	Scans full system / folder / single file using SHA‑256 hash signatures. Quarantines infected files.
File Locker	Encrypt/decrypt any file using AES‑256 (Fernet). Encrypted files are saved in a safe folder.
Firewall	Real‑time background process monitor. Detects suspicious processes with no visible window (e.g., hidden malware) running from Downloads/AppData/Temp and asks to block/kill.
USB Scanner	Automatically detects removable drives, asks for a password, then scans the drive for malware. Wrong password → attempts to block the drive using mountvol, diskpart, and icacls (best effort).
System Cleaner	Finds and removes temporary / cache files older than 7 days from common locations (Temp, Prefetch, browser caches). Moves them to quarantine instead of permanent delete by default.
System Lockdown	Locks the system with a full‑screen overlay for a set number of minutes. Only the user can end it early.
Patch Monitor	Checks Windows Update service status and retrieves the date of the last installed update (via Get-HotFix or Event Logs). Shows how many days ago the last patch was installed.
Password Vault	Securely stores account passwords in encrypted files (AES‑256). Requires a master password (default "5040" – change it!).

# 🧠 Code Architecture & Details
Project Structure (as of latest version)
text
GhostWall/
├── ghostwallGui.py          # Main GUI application (Tkinter)
├── ghostwallWithoutGui.py   # Console‑only version (for legacy/headless)
├── GhostWall_Data/          # Auto‑created on first run (portable)
│   ├── signatures/          # SHA‑256 hash files (pack1.txt, etc.)
│   ├── Quarantine/          # Moved suspicious/temp files
│   ├── safefiles/           # Encrypted/decrypted files
│   ├── passwords/           # Encrypted password vault entries
│   └── logs/                # Malware scan logs
└── requirements.txt         # Python dependencies
How the Portable Path System Works
In the improved (portable) version, all paths are relative to the script’s location:
python
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(SCRIPT_DIR, "GhostWall_Data")
SIGNATURES_DIR = os.path.join(DATA_DIR, "signatures")


# etc.
If a folder doesn’t exist, it is created automatically.
If you are using a version with hardcoded D:\antivirus\... paths, you must either:
Move your files to D:\antivirus\ (not recommended for other users), or
Replace those absolute paths with the portable logic above (instructions below).
Key Functions Explained
load_signatures() – Reads all .txt files from signatures/ and builds a set of SHA‑256 hashes (lowercase).
scan_file() – Calculates SHA‑256 of a file, compares with signatures, quarantines on match.
firewall_monitor() – Runs in a background thread, iterates over running processes, identifies suspicious ones (no window + path in Downloads/AppData/Temp), asks user.
usb_scanner_background() – Polls every 2 seconds for new removable drives, then spawns a thread to ask password and scan.
patch_monitor() – Uses subprocess with shell=True to run PowerShell commands reliably from the GUI thread.
password_vault_ui() – Custom Tkinter dialog for saving/retrieving passwords, all encrypted with the master password.
Threading & GUI Safety
Because Tkinter is not thread‑safe, all GUI operations (popups, file dialogs) are routed through a queue (_gui_call_queue) and processed in the main thread using run_in_gui_thread(). Background tasks (scans, firewall) run in daemon threads.

# 📦 Requirements
Operating System: Windows 10 / 11 (some features like USB blocking require admin rights, but core scanning works without).
Python: 3.8 or higher (3.12 recommended).
Required libraries (install via pip):
text
cryptography
psutil
pywin32
watchdog
pandas
tkinter is included with standard Python on Windows.

# 🔧 Installation
Clone or download this repository:
bash
git clone https://github.com/your-username/GhostWall-Antivirus.git
cd GhostWall-Antivirus
(Recommended) Create a virtual environment (optional but clean):
bash
python -m venv venv
venv\Scripts\activate
Install dependencies:
bash
pip install -r requirements.txt
If you don’t have a requirements.txt yet, create one with:
text
cryptography
psutil
pywin32
watchdog
pandas
Prepare signature files – GhostWall expects signature files inside GhostWall_Data/signatures/. If you don’t have any, the program will create empty template files. To actually detect malware, you need to populate these files with SHA‑256 hashes of known malware (one per line). You can find public malware hash databases (e.g., from VirusTotal, Malshare). For testing, add a few hashes of benign files.

# ▶️ Running GhostWall
Graphical Interface (Recommended)
bash
python ghostwallGui.py
The main window will appear. All features are accessible via buttons. Output is shown in the right panel.
Console‑Only Version (for servers or remote connections)
bash
python ghostwallWithoutGui.py
All interaction happens via the terminal. The USB scanner still works (popups may appear if Tkinter is installed).

# ⚙️ Configuration & Paths (IMPORTANT)
🔸 If you are using the portable version (the one with GhostWall_Data):
No changes required – everything is relative to the script. Just run it.
The data folder will be created automatically next to the .py file.
🔸 If your code still has hardcoded absolute paths like D:\antivirus\...:
You must change them. Here’s how:
Open ghostwallGui.py.
Locate these lines near the top:
python
PASS_DIR = r"D:\antivirus\pass"
SAFE_FOLDER = r"D:\antivirus\safefiles"
QUARANTINE_FOLDER = r"D:\antivirus\Quarantine"
SIGNATURE_PATHS = [r"D:\antivirus\signatures\SHA256-Hashes_pack1.txt", ...]
LOG_FILE = r"D:\antivirus\malware_scan_log.txt"
Replace them with the portable code:
python
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(SCRIPT_DIR, "GhostWall_Data")
os.makedirs(DATA_DIR, exist_ok=True)
PASS_DIR = os.path.join(DATA_DIR, "passwords")
SAFE_FOLDER = os.path.join(DATA_DIR, "safefiles")
QUARANTINE_FOLDER = os.path.join(DATA_DIR, "Quarantine")
SIGNATURES_DIR = os.path.join(DATA_DIR, "signatures")
LOG_FILE = os.path.join(DATA_DIR, "logs", "malware_scan_log.txt")
SIGNATURE_PATHS = [
    os.path.join(SIGNATURES_DIR, "SHA256-Hashes_pack1.txt"),
    os.path.join(SIGNATURES_DIR, "SHA256-Hashes_pack2.txt"),
    os.path.join(SIGNATURES_DIR, "SHA256-Hashes_pack3.txt"),
]
Also create the directories:
python
os.makedirs(PASS_DIR, exist_ok=True)
os.makedirs(SAFE_FOLDER, exist_ok=True)
os.makedirs(QUARANTINE_FOLDER, exist_ok=True)
os.makedirs(SIGNATURES_DIR, exist_ok=True)
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)


# 🔸 Changing the USB / Master Password
USB_PASSWORD = "5040" – change this to your preferred USB password.
MASTER_PASSWORD = "5040" – change this to secure the password vault.
Never share your passwords – they are stored encrypted, but the master password is in plain text in the code if you don’t change it. Ideally, move it to a config file or environment variable.

# 🔸 Adding Your Own Malware Signatures
Place .txt files in GhostWall_Data/signatures/.
Each line should be a SHA‑256 hash (lowercase).
You can download public malware hash sets (e.g., from VirusTotal or Malshare) and convert them to SHA‑256.

# 📝 Important Notes
Administrator privileges are required for reliable USB blocking and some firewall operations (killing processes). Without admin, the USB blocker may fail, and the firewall might not be able to terminate processes. GhostWall will warn you but still run other features.
The firewall only monitors background processes with no visible window that run from suspicious locations (Downloads, Desktop, AppData, Temp). System processes and signed software in Program Files are ignored.
System Cleaner only targets temp/cache folders – it never touches your Documents, Desktop, etc. Deleted files go to quarantine by default.
Patch Monitor uses PowerShell commands (Get-HotFix, Event Logs). If you have never installed any Windows Update, it may show “unable to determine last patch date”. That’s expected.
Password Vault uses AES‑256 encryption. The master password is hardcoded in the example – you must change it before using the vault in a production environment.

# 🤝 Contributing
Feel free to fork this repository, open issues, or submit pull requests. Areas for improvement:
Add a settings window to change passwords/paths.
Use a config file instead of hardcoded defaults.
Improve signature update mechanism (download from a remote source).
Add a scheduled scan feature.

# 📄 License
This project is licensed under the MIT License – see the LICENSE file for details.
Disclaimer: GhostWall is provided for educational and personal use only. The authors are not responsible for any damage or data loss caused by this software. Always test in a safe environment first.
