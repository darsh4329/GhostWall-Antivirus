# =====================================================
# 🛡️ GhostWall - Antivirus Toolkit (Complete Single File)
# =====================================================
# Features:
#  - Malware Scanner (full/folder/file) with progress & logs
#  - File Locker (encrypt / decrypt)
#  - Firewall (auto-encrypt downloads + blocklist)
#  - USB Scanner (always-on, popup password, strong blocking attempts)
#  - System Cleaner (console-only)
#  - System Lockdown, Patch Monitor, Password Vault
# =====================================================

import os
import psutil
import base64
import hashlib
import time
import shutil
import subprocess
import threading
import ctypes
import sys
import tkinter as tk
import socket
from tkinter import simpledialog, messagebox
from datetime import datetime, timedelta
import atexit
from tkinter import filedialog
from cryptography.fernet import Fernet
import queue  # NEW: for GUI call queue

PASS_DIR = r"D:\antivirus\pass"
MASTER_PASSWORD = "5040"

# ---------------- Tk root (GUI thread) ----------------
root = tk.Tk()
root.withdraw()  # keep hidden, we use dialogs and custom windows

# Queue for GUI calls from other threads
_gui_call_queue = queue.Queue()
def ask_patch_days_popup(default=30):
    try:
        return run_in_gui_thread(
            simpledialog.askinteger,
            "Patch Monitor",
            "Enter threshold in days:",
            initialvalue=default,
            minvalue=1
        )
    except Exception:
        return None

def _is_main_thread():
    return threading.current_thread() is threading.main_thread()

def run_in_gui_thread(fn, *args, **kwargs):
    """
    Run a callable in the Tk main (GUI) thread and return its result.
    Other threads block until the GUI thread completes the function.
    """
    if _is_main_thread():
        # Already in GUI thread
        return fn(*args, **kwargs)

    event = threading.Event()
    container = {}

    _gui_call_queue.put((fn, args, kwargs, event, container))
    event.wait()  # wait until GUI thread finishes

    if "exc" in container:
        raise container["exc"]
    return container.get("result")

def _process_gui_calls():
    """
    Periodically called in the GUI thread to process queued GUI operations.
    """
    try:
        while True:
            fn, args, kwargs, event, container = _gui_call_queue.get_nowait()
            try:
                res = fn(*args, **kwargs)
                container["result"] = res
            except Exception as e:
                container["exc"] = e
            finally:
                event.set()
    except queue.Empty:
        pass
    # schedule again
    root.after(50, _process_gui_calls)

def ask_lockdown_minutes_popup():
    try:
        return run_in_gui_thread(
            simpledialog.askfloat,
            "System Lockdown",
            "Enter lockdown duration (in minutes):",
            minvalue=1.0
        )
    except Exception:
        return None

# Clean up Tkinter safely on program exit
@atexit.register
def cleanup_tk():
    try:
        root.destroy()
    except:
        pass

# Optional: pandas / watchdog used by firewall features; import only if available
try:
    import pandas as pd
except Exception:
    pd = None

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except Exception:
    Observer = None
    FileSystemEventHandler = object

# Force UTF-8 output on Windows consoles
try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

# ---------------- PATH / CONFIG ----------------
SAFE_FOLDER = r"D:\antivirus\safefiles"
QUARANTINE_FOLDER = r"D:\antivirus\Quarantine"
BLOCKLIST_PATH = r"D:\antivirus\blocksites\malicious_phish_cleaned_updated.csv"
DOWNLOADS_FOLDER = os.path.join(os.path.expanduser("~"), "Downloads")
ENCRYPTION_PASSWORD = "5040"
USB_PASSWORD = "5040"  # stored password for USB
SIGNATURE_PATHS = [
    r"D:\antivirus\signatures\SHA256-Hashes_pack1.txt",
    r"D:\antivirus\signatures\SHA256-Hashes_pack2.txt",
    r"D:\antivirus\signatures\SHA256-Hashes_pack3.txt",
]
LOG_FILE = r"D:\antivirus\malware_scan_log.txt"

# Cleaner defaults
CLEANER_DEFAULT_AGE_DAYS = 7  # only consider files older than X days
CLEANER_EXTENSIONS = {
    ".tmp", ".log", ".bak", ".old", ".gid", ".chk", ".dmp", ".partial", ".crdownload", ".~"
}
CLEANER_ADD_PATTERNS = [
    "thumbcache",  # thumbnail cache DBs
    "tmp",         # temp dirs
    "cache",
    "prefetch",
    "temporary internet files",
]

# Ensure required folders exist
os.makedirs(SAFE_FOLDER, exist_ok=True)
os.makedirs(QUARANTINE_FOLDER, exist_ok=True)
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# ---------------- admin check ----------------
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def _popup_info_impl(msg, title="Info"):
    root.deiconify()
    root.lift()
    root.attributes("-topmost", True)
    root.focus_force()
    messagebox.showinfo(title, msg, parent=root)
    root.attributes("-topmost", False)
    root.withdraw()

def _popup_warning_impl(msg, title="Warning"):
    root.deiconify()
    root.lift()
    root.attributes("-topmost", True)
    root.focus_force()
    messagebox.showwarning(title, msg, parent=root)
    root.attributes("-topmost", False)
    root.withdraw()

def _popup_error_impl(msg, title="Error"):
    root.deiconify()
    root.lift()
    root.attributes("-topmost", True)
    root.focus_force()
    messagebox.showerror(title, msg, parent=root)
    root.attributes("-topmost", False)
    root.withdraw()

def popup_info(msg, title="Info"):
    run_in_gui_thread(_popup_info_impl, msg, title)

def popup_warning(msg, title="Warning"):
    run_in_gui_thread(_popup_warning_impl, msg, title)

def popup_error(msg, title="Error"):
    run_in_gui_thread(_popup_error_impl, msg, title)

def show_admin_warning():
    popup_warning(
        "GhostWall is not running with Administrator privileges.\n"
        "For reliable USB blocking and permission changes, run GhostWall as Administrator.",
        "Administrator Recommended"
    )

def human_size(n):
    try:
        n = int(n)
    except Exception:
        return "?"
    for unit in ['B','KB','MB','GB','TB']:
        if n < 1024:
            return f"{n}{unit}"
        n = n // 1024
    return f"{n}PB"

def file_age_days(path):
    try:
        mtime = os.path.getmtime(path)
        return (time.time() - mtime) / (60*60*24)
    except Exception:
        return float('inf')
    
# ---------- internal helpers ----------
def _derive_key(master_pass: str) -> bytes:
    h = hashlib.sha256(master_pass.encode()).digest()
    return base64.urlsafe_b64encode(h)

def _encrypt_text(text: str, master_pass: str) -> bytes:
    key = _derive_key(master_pass)
    return Fernet(key).encrypt(text.encode())

def _decrypt_text(cipher: bytes, master_pass: str) -> str:
    key = _derive_key(master_pass)
    return Fernet(key).decrypt(cipher).decode()

# =====================================================
# 🧩 MALWARE SCANNERs
# =====================================================
def load_signatures():
    signatures = set()
    for path in SIGNATURE_PATHS:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        sig = line.strip().lower()
                        if sig:
                            signatures.add(sig)
            except Exception:
                with open(path, "r", errors="ignore") as f:
                    for line in f:
                        sig = line.strip().lower()
                        if sig:
                            signatures.add(sig)
        else:
            print(f"⚠️ Signature file missing: {path}")
    print(f"🧾 Loaded {len(signatures)} virus signatures.")
    return signatures

def calculate_sha256(file_path):
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return None

def quarantine_file(file_path):
    try:
        if not os.path.exists(QUARANTINE_FOLDER):
            os.makedirs(QUARANTINE_FOLDER)
        filename = os.path.basename(file_path)
        dest = os.path.join(QUARANTINE_FOLDER, filename)
        if os.path.exists(dest):
            base, ext = os.path.splitext(filename)
            dest = os.path.join(QUARANTINE_FOLDER, f"{base}_{int(time.time())}{ext}")
        shutil.move(file_path, dest)
        print(f"⚠️ File quarantined: {dest}")
    except Exception as e:
        print(f"❌ Failed to quarantine {file_path}: {e}")

def scan_file(file_path, signatures, log_writer=None):
    if not os.path.exists(file_path):
        print(f"❌ File not found: {file_path}")
        if log_writer:
            log_writer.write(f"❌ File not found: {file_path}\n")
        return False

    file_hash = calculate_sha256(file_path)
    if not file_hash:
        print(f"⚠️ Could not read: {file_path}")
        if log_writer:
            log_writer.write(f"⚠️ Could not read: {file_path}\n")
        return False

    if file_hash.lower() in signatures:
        print(f"🚨 INFECTED: {file_path}")
        if log_writer:
            log_writer.write(f"🚨 INFECTED: {file_path}\n")
        quarantine_file(file_path)
        return True
    else:
        print(f"✅ CLEAN: {file_path}")
        if log_writer:
            log_writer.write(f"✅ CLEAN: {file_path}\n")
        return False

def scan_system(signatures, scan_path=None):
    """
    Scan a path (drive/folder) or full system if scan_path is None.
    """
    if scan_path:
        paths_to_scan = [scan_path]
    else:
        paths_to_scan = [disk.device for disk in psutil.disk_partitions() if "fixed" in disk.opts.lower()]
        if not paths_to_scan:
            paths_to_scan = ["C:\\"]

    all_files = []
    for path in paths_to_scan:
        for root_dir, _, files in os.walk(path):
            for f in files:
                all_files.append(os.path.join(root_dir, f))
    total_count = len(all_files)

    scanned = 0
    infected = 0

    try:
        log = open(LOG_FILE, "a", encoding="utf-8")
    except Exception:
        log = open(LOG_FILE, "a", errors="ignore")

    log.write(f"\n=== Scan Started: {time.ctime()} Path: {scan_path or 'Full System'} ===\n")
    try:
        for idx, file_path in enumerate(all_files, start=1):
            scanned += 1
            percent = (idx / total_count) * 100 if total_count else 100
            print(f"🔍 Scanning: {file_path} ({idx}/{total_count}) [{percent:.2f}%]")
            infected_found = scan_file(file_path, signatures, log)
            if infected_found:
                infected += 1
    finally:
        log.write(f"\n=== Scan Completed: {time.ctime()} Scanned: {scanned} Infected: {infected} ===\n")
        log.close()

    print("\n🧩 Scan complete.")
    print(f"📊 Summary: Scanned {scanned} files — Infected {infected}")
    try:
        popup_info(f"Scan complete.\nScanned: {scanned}\nInfected: {infected}", "Scan Complete")
    except Exception:
        pass

def scan_folder(folder_path, signatures):
    scan_system(signatures, scan_path=folder_path)

# =====================================================
# 🧩 FILE LOCKER
# =====================================================

def show_progress(task):
    print(f"\n{task} Please wait", end="")
    for _ in range(5):
        time.sleep(0.4)
        print(".", end="", flush=True)
    print("\n")

def encrypt_file():
    file_path = input("\nEnter file path to encrypt: ").strip()
    if not os.path.exists(file_path):
        print("❌ File not found.")
        return
    password = input("Enter password: ").strip()
    key = hashlib.sha256(password.encode()).digest()
    fernet_key = base64.urlsafe_b64encode(key)
    from cryptography.fernet import Fernet as FernetLocal
    fernet = FernetLocal(fernet_key)
    with open(file_path, "rb") as f:
        data = f.read()
    show_progress("Encrypting")
    encrypted = fernet.encrypt(data)
    encrypted_path = os.path.join(SAFE_FOLDER, os.path.basename(file_path) + ".enc")
    with open(encrypted_path, "wb") as f:
        f.write(encrypted)
    os.remove(file_path)
    print(f"✅ Encrypted & saved to: {encrypted_path}")

def decrypt_file():
    file_path = input("\nEnter encrypted file (.enc) path: ").strip()
    if not os.path.exists(file_path):
        print("❌ File not found.")
        return
    password = input("Enter password: ").strip()
    key = hashlib.sha256(password.encode()).digest()
    fernet_key = base64.urlsafe_b64encode(key)
    from cryptography.fernet import Fernet as FernetLocal
    fernet = FernetLocal(fernet_key)
    try:
        with open(file_path, "rb") as f:
            encrypted = f.read()
        show_progress("Decrypting")
        decrypted = fernet.decrypt(encrypted)
        decrypted_path = os.path.join(SAFE_FOLDER, "decrypted_" + os.path.basename(file_path).replace(".enc", ""))
        with open(decrypted_path, "wb") as f:
            f.write(decrypted)
        os.remove(file_path)
        print(f"✅ Decrypted file saved to: {decrypted_path}")
    except Exception:
        print("❌ Wrong password or corrupted file.")

# ---------------- Firewall (auto-encrypt downloads + blocklist) ----------------
# =====================================================
# 🔥 UI-AWARE PROCESS FIREWALL (SAFE)
# =====================================================

FIREWALL_ENABLED = False

# Processes user allowed for THIS SESSION
SESSION_ALLOW = set()

# Never touch system / harmless apps
SAFE_PROCESS_NAMES = {
    "explorer.exe",
    "svchost.exe",
    "lsass.exe",
    "services.exe",
    "wininit.exe",
    "winlogon.exe",
    "csrss.exe",
    "smss.exe",
    "taskmgr.exe",
    "python.exe",
    "pythonw.exe",
}
SUSPICIOUS_LOCATIONS = [
    os.path.join(os.path.expanduser("~"), "downloads").lower(),
    os.path.join(os.path.expanduser("~"), "desktop").lower(),
    os.path.join(os.path.expanduser("~"), "appdata").lower(),
    os.environ.get("temp", "").lower(),
]


SAFE_PATH_KEYWORDS = [
    r"c:\windows",
    r"c:\program files",
    r"c:\program files (x86)",
]


def process_has_visible_window(pid):
    try:
        import win32gui
        import win32process

        visible = False

        def callback(hwnd, _):
            nonlocal visible
            _, win_pid = win32process.GetWindowThreadProcessId(hwnd)
            if win_pid == pid and win32gui.IsWindowVisible(hwnd):
                visible = True

        win32gui.EnumWindows(callback, None)
        return visible
    except Exception:
        return True  # fail-safe

def is_safe_process(proc):
    """
    Returns True if the process is considered SAFE
    (system, program files, signed-looking behavior)
    """
    try:
        name = proc.name().lower()
        exe = (proc.exe() or "").lower()

        # Known safe process names
        if name in SAFE_PROCESS_NAMES:
            return True

        # Windows / Program Files
        for path in SAFE_PATH_KEYWORDS:
            if exe.startswith(path):
                return True

        # No executable path (very common for system services)
        if not exe or exe.strip() == "":
            return True

        return False
    except Exception:
        return True

def is_highly_suspicious(proc):
    """
    Returns True ONLY for processes that are
    very likely to be malicious.
    """
    try:
        exe = (proc.exe() or "").lower()

        # Must be running from high-risk user locations
        for loc in SUSPICIOUS_LOCATIONS:
            if exe.startswith(loc):
                return True

        return False
    except Exception:
        return False



def firewall_user_popup(proc):
    def _ask():
        root.deiconify()
        root.lift()
        root.attributes("-topmost", True)
        root.focus_force()

        msg = (
            "⚠️ SUSPICIOUS BACKGROUND PROCESS DETECTED ⚠️\n\n"
            f"Name: {proc.name()}\n"
            f"PID: {proc.pid}\n"
            f"Path: {proc.exe()}\n\n"
            "This process has NO visible window.\n\n"
            "Do you want GhostWall to BLOCK this process?"
        )

        result = messagebox.askyesno(
            "GhostWall Firewall Alert",
            msg,
            parent=root
        )

        root.attributes("-topmost", False)
        root.withdraw()
        return result

    return run_in_gui_thread(_ask)


def firewall_monitor():
    print("🔥 GhostWall UI-Aware Firewall ACTIVE")
    checked = set()

    while FIREWALL_ENABLED:
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                if proc.pid in checked:
                    continue
                checked.add(proc.pid)

                if is_safe_process(proc):
                    continue

                exe = (proc.exe() or "").lower()
                if exe in SESSION_ALLOW:
                    continue

                if process_has_visible_window(proc.pid):
                    continue

                if not is_highly_suspicious(proc):
                    continue
                decision = firewall_user_popup(proc)


                if decision:
                    try:
                        proc.kill()
                        popup_warning(
                            f"Blocked background process:\n{proc.name()}",
                            "Firewall Blocked"
                        )
                    except Exception:
                        pass
                else:
                    SESSION_ALLOW.add(exe)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception:
                continue

        time.sleep(2)


def firewall():
    global FIREWALL_ENABLED

    if FIREWALL_ENABLED:
        popup_info("Firewall already running.", "GhostWall Firewall")
        return

    enable = run_in_gui_thread(
        messagebox.askyesno,
        "Enable Firewall",
        "Enable GhostWall UI-Aware Firewall?\n\n"
        "You will be asked before blocking any background process."
    )

    if not enable:
        return

    FIREWALL_ENABLED = True

    threading.Thread(
        target=firewall_monitor,
        daemon=True
    ).start()

    popup_info(
        "Firewall ENABLED.\n\n"
        "GhostWall is now monitoring background processes in real time.",
        "Firewall Active"
    )

# =====================================================
# 🧩 USB SCANNER
# =====================================================
def _is_drive_readable(drive_letter):
    try:
        os.listdir(drive_letter)
        return True
    except Exception:
        return False

def _run_command(cmd, timeout=10):
    try:
        proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        out = proc.stdout.decode(errors='ignore') if proc.stdout else ""
        err = proc.stderr.decode(errors='ignore') if proc.stderr else ""
        return proc.returncode, out, err
    except Exception as e:
        return -1, "", str(e)

def block_drive_strong(drive_letter, attempts=3, pause=0.8):
    drive = drive_letter.rstrip("\\")
    # 1) mountvol /p
    for _ in range(attempts):
        _run_command(f'mountvol {drive} /p')
        time.sleep(pause)
        if not _is_drive_readable(drive_letter):
            return True

    # 2) diskpart remove letter=<letter>
    script_name = os.path.join(os.getenv("TEMP", "C:\\Windows\\Temp"), f"dp_{int(time.time())}.txt")
    try:
        letter = drive.rstrip(":").upper()
        with open(script_name, "w") as s:
            s.write(f"remove letter={letter}\n")
        _run_command(f'diskpart /s "{script_name}"', timeout=12)
        time.sleep(pause)
        if not _is_drive_readable(drive_letter):
            return True
    except Exception:
        pass
    finally:
        try:
            if os.path.exists(script_name):
                os.remove(script_name)
        except Exception:
            pass

    # 3) icacls deny Everyone:(OI)(CI)F /T
    for _ in range(attempts):
        cmd = f'icacls "{drive_letter}" /deny Everyone:(OI)(CI)F /T'
        _run_command(cmd, timeout=12)
        time.sleep(pause)
        if not _is_drive_readable(drive_letter):
            return True

    # 4) mountvol /d
    for _ in range(attempts):
        _run_command(f'mountvol {drive} /d')
        time.sleep(pause)
        if not _is_drive_readable(drive_letter):
            return True

    return False

def hide_usb_drive_strong(drive_letter):
    popup_info(f"Attempting to block USB {drive_letter} (best-effort)...", "Blocking USB")
    success = block_drive_strong(drive_letter, attempts=3, pause=0.9)
    if success:
        popup_info(f"USB {drive_letter} blocked (best-effort).", "USB Blocked")
        print(f"🔒 USB {drive_letter} blocked.")
    else:
        popup_error(
            "Could not fully block the USB programmatically.\n"
            "This usually means GhostWall is not running as Administrator or another process holds files open.\n"
            "Run GhostWall as Administrator for reliable blocking.",
            "USB Block Incomplete"
        )
        print(f"⚠️ Failed to fully block USB {drive_letter}.")

# ---------------- USB password dialog (GUI thread) ----------------
def _usb_password_dialog_impl(drive):
    """
    GUI-thread-only: creates a custom focused dialog to ask USB password.
    """
    top = tk.Toplevel(root)
    top.title("USB Password")
    top.attributes("-topmost", True)
    top.lift()
    top.focus_force()
    top.grab_set()

    top.configure(bg="black")

    label = tk.Label(
        top,
        text=f"Enter password for USB {drive}:",
        font=("Segoe UI", 12),
        fg="white",
        bg="black",
        pady=10
    )
    label.pack(padx=20, pady=(15, 5))

    entry = tk.Entry(top, show="*", font=("Segoe UI", 12), width=25)
    entry.pack(padx=20, pady=5)
    entry.focus_set()

    result = {"pwd": None}

    def on_ok():
        result["pwd"] = entry.get().strip()
        top.destroy()

    def on_cancel():
        result["pwd"] = None
        top.destroy()

    btn_frame = tk.Frame(top, bg="black")
    btn_frame.pack(pady=15)

    ok_btn = tk.Button(btn_frame, text="OK", width=10, command=on_ok)
    ok_btn.pack(side="left", padx=5)

    cancel_btn = tk.Button(btn_frame, text="Cancel", width=10, command=on_cancel)
    cancel_btn.pack(side="left", padx=5)

    top.bind("<Return>", lambda event: on_ok())
    top.bind("<Escape>", lambda event: on_cancel())

    # Center on screen
    top.update_idletasks()
    w = top.winfo_width()
    h = top.winfo_height()
    sw = top.winfo_screenwidth()
    sh = top.winfo_screenheight()
    x = (sw - w) // 2
    y = (sh - h) // 2
    top.geometry(f"+{x}+{y}")

    top.mainloop() if False else None  # we already have global root.mainloop

    top.wait_window()
    return result["pwd"]

def ask_usb_password_popup(drive):
    """
    Thread-safe wrapper: any thread can call this to get USB password.
    It will execute the custom dialog in the GUI thread and return the password.
    """
    return run_in_gui_thread(_usb_password_dialog_impl, drive)

def usb_scan_worker(drive):
    signatures = load_signatures()
    pwd = ask_usb_password_popup(drive)
    if pwd != USB_PASSWORD:
        print("❌ Incorrect USB password. Blocking USB.")
        hide_usb_drive_strong(drive)
        return
    popup_info(f"Password accepted. Scanning USB {drive} now...", "USB Scan")
    scan_system(signatures, scan_path=drive)

def list_removable_drives():
    removable = set()
    for part in psutil.disk_partitions(all=False):
        drive_letter = part.device
        try:
            DRIVE_REMOVABLE = 2
            if ctypes.windll.kernel32.GetDriveTypeW(drive_letter) == DRIVE_REMOVABLE:
                removable.add(drive_letter)
        except Exception:
            if 'removable' in part.opts.lower():
                removable.add(drive_letter)
    return removable

def usb_scanner_background():
    observed = set()
    while True:
        try:
            current = list_removable_drives()
            new = current - observed
            if new:
                for drive in new:
                    print(f"\n💽 USB Detected: {drive}")
                    t = threading.Thread(target=usb_scan_worker, args=(drive,), daemon=True)
                    t.start()
            observed = current
        except Exception as e:
            print("⚠️ USB monitor error:", e)
        time.sleep(2)

# =====================================================
# 🧹 SYSTEM CLEANER
# =====================================================
def gather_cleaner_candidate_paths():
    paths = set()

    for var in ("TEMP", "TMP"):
        val = os.environ.get(var)
        if val:
            paths.add(val)

    user_temp = os.path.join(os.path.expanduser("~"), "AppData", "Local", "Temp")
    paths.add(user_temp)

    system_temp = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "Temp")
    paths.add(system_temp)

    prefetch = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "Prefetch")
    paths.add(prefetch)

    explorer_cache = os.path.join(os.path.expanduser("~"), "AppData", "Local", "Microsoft", "Windows", "Explorer")
    paths.add(explorer_cache)

    local_appdata = os.path.join(os.path.expanduser("~"), "AppData", "Local")
    browser_cache_candidates = [
        os.path.join(local_appdata, "Google", "Chrome", "User Data", "Default", "Cache"),
        os.path.join(local_appdata, "Mozilla", "Firefox", "Profiles"),
        os.path.join(local_appdata, "Microsoft", "Edge", "User Data", "Default", "Cache"),
    ]
    for p in browser_cache_candidates:
        paths.add(p)

    paths.add(os.path.join(os.path.expanduser("~"), "AppData", "Local", "Microsoft", "Windows", "INetCache"))

    return [p for p in paths if os.path.exists(p)]

def _protected_paths_set():
    up = os.path.expanduser("~")
    prot = set()
    for name in ("Desktop", "Documents", "Downloads", "Pictures", "Music", "Videos"):
        prot.add(os.path.abspath(os.path.join(up, name)))
    prot.add(os.path.abspath(SAFE_FOLDER))
    prot.add(os.path.abspath(QUARANTINE_FOLDER))
    prot.add(os.path.abspath(os.path.dirname(LOG_FILE)))
    prot.add(os.path.abspath(up))
    return {p for p in prot if os.path.exists(p)}

def _is_path_under(base, path):
    try:
        base_abs = os.path.abspath(base)
        path_abs = os.path.abspath(path)
        common = os.path.commonpath([base_abs, path_abs])
        return common == base_abs
    except Exception:
        return False

def is_protected_path(path, protected=None):
    if protected is None:
        protected = _protected_paths_set()
    path_abs = os.path.abspath(path)
    for p in protected:
        try:
            if _is_path_under(p, path_abs):
                return True
        except Exception:
            continue
    return False

def find_useless_files(paths, age_days=CLEANER_DEFAULT_AGE_DAYS,
                       extensions=CLEANER_EXTENSIONS,
                       add_patterns=CLEANER_ADD_PATTERNS):
    candidates = []
    cutoff = time.time() - (age_days * 24 * 60 * 60)
    protected = _protected_paths_set()
    for base in paths:
        base_abs = os.path.abspath(base)
        for root_dir, _, files in os.walk(base_abs):
            for f in files:
                try:
                    full = os.path.join(root_dir, f)
                    if not _is_path_under(base_abs, full):
                        continue
                    if os.path.islink(full):
                        continue
                    if is_protected_path(full, protected=protected):
                        continue
                    st = os.stat(full)
                    if st.st_mtime > cutoff:
                        continue
                    lower = f.lower()
                    ext = os.path.splitext(f)[1].lower()
                    path_lower = full.lower()
                    matched = False
                    if ext in extensions:
                        matched = True
                    else:
                        for pat in add_patterns:
                            if pat in path_lower or pat in lower:
                                matched = True
                                break
                    if matched:
                        candidates.append({
                            "path": full,
                            "size": st.st_size,
                            "age_days": (time.time() - st.st_mtime) / (24*3600)
                        })
                except Exception:
                    continue
    candidates.sort(key=lambda x: (-x["age_days"], -x["size"]))
    unique = []
    seen = set()
    for c in candidates:
        if c["path"] not in seen:
            unique.append(c)
            seen.add(c["path"])
    return unique

def print_candidates(candidates):
    if not candidates:
        print("\nNo candidate 'useless' files found based on current rules/age.")
        return
    print("\nFound candidate files (older than {} days):".format(CLEANER_DEFAULT_AGE_DAYS))
    for i, c in enumerate(candidates, start=1):
        age = int(c["age_days"])
        print(f"{i:3}. [{human_size(c['size']):>6}] {age:3}d  {c['path']}")

def parse_selection(inp, max_n):
    inp = inp.strip().lower()
    if not inp:
        return set()
    if inp == "all":
        return set(range(1, max_n+1))
    if inp == "none":
        return set()
    parts = inp.split(",")
    sel = set()
    for p in parts:
        p = p.strip()
        if "-" in p:
            try:
                a, b = p.split("-", 1)
                a = int(a); b = int(b)
                if a < 1: a = 1
                if b > max_n: b = max_n
                if a <= b:
                    for x in range(a, b+1):
                        sel.add(x)
            except Exception:
                continue
        else:
            try:
                v = int(p)
                if 1 <= v <= max_n:
                    sel.add(v)
            except Exception:
                continue
    return sel

def perform_cleaning(selected_indices, candidates, move_to_quarantine=True):
    done = []
    failed = []
    protected = _protected_paths_set()
    for idx in sorted(selected_indices):
        try:
            c = candidates[idx-1]
            src = c["path"]
            if is_protected_path(src, protected=protected):
                failed.append((src, "Path is protected; skipping"))
                continue
            if move_to_quarantine:
                if not os.path.exists(QUARANTINE_FOLDER):
                    os.makedirs(QUARANTINE_FOLDER, exist_ok=True)
                base = os.path.basename(src)
                dest = os.path.join(QUARANTINE_FOLDER, base)
                if os.path.exists(dest):
                    base_name, ext = os.path.splitext(base)
                    dest = os.path.join(QUARANTINE_FOLDER, f"{base_name}_{int(time.time())}{ext}")
                shutil.move(src, dest)
                done.append(("moved", src, dest))
            else:
                os.remove(src)
                done.append(("deleted", src, None))
        except Exception as e:
            failed.append((c["path"] if 'c' in locals() else "unknown", str(e)))
    return done, failed

def system_cleaner_menu():
    print("\n=== 🧹 System Cleaner (Console Only) ===")
    print("This module finds common 'temporary' and cache files and offers to move them to quarantine or permanently delete them.")
    print("SAFE-BY-DEFAULT: Candidates are files older than {} days and located in temp/cache locations.\n".format(CLEANER_DEFAULT_AGE_DAYS))

    paths = gather_cleaner_candidate_paths()
    if not paths:
        print("⚠️ No known temp/cache directories found on this system.")
        return

    print("Scanning these locations (if present):")
    for p in paths:
        print(" -", p)
    print("\nScanning, please wait...\n")

    candidates = find_useless_files(paths, age_days=CLEANER_DEFAULT_AGE_DAYS)
    if not candidates:
        print("✅ Nothing to clean (no matching candidates found).")
        return

    total_bytes = sum(c['size'] for c in candidates)
    total_count = len(candidates)
    print(f"\nFound {total_count} candidate file(s), total size: {human_size(total_bytes)}")
    print("Note: Only files under temp/cache paths are considered. User folders are protected.\n")

    print_candidates(candidates)

    while True:
        sel_input = input("\nEnter numbers to remove (e.g. 1,3-5), 'all' to select all, or 'none' to cancel: ").strip()
        selected = parse_selection(sel_input, len(candidates))
        if selected is None:
            print("X Invalid selection. Try again. X")
            continue
        if not selected:
            print("No files selected. Cancelled.")
            return
        print("\nYou selected {} item(s):".format(len(selected)))
        total_selected_bytes = 0
        for i in sorted(selected):
            c = candidates[i-1]
            total_selected_bytes += c.get('size', 0)
            print(f" - {c['path']} ({human_size(c['size'])}, {int(c['age_days'])}d)")
        print(f"\nSelected total size: {human_size(total_selected_bytes)}")
        confirm = input("\nProceed? (y/n): ").strip().lower()
        if confirm == "y":
            break
        else:
            print("Selection cancelled. You can re-enter or type 'none' to abort.")
            continue

    while True:
        action = input("\nAction - move to Quarantine (q) [RECOMMENDED] or permanently delete (p)? (q/p): ").strip().lower()
        if action not in ("q", "p"):
            print("Please enter 'q' or 'p'.")
            continue
        move_to_quarantine = (action == "q")
        if move_to_quarantine:
            print("\nMoving files to QUARANTINE:", QUARANTINE_FOLDER)
        else:
            print("\nPERMANENT DELETE selected.")
            ack = input("Type 'DELETE' to confirm permanent deletion (case-sensitive), anything else to cancel: ")
            if ack != "DELETE":
                print("Permanent delete aborted. Defaulting to move to quarantine.")
                move_to_quarantine = True
        break

    done, failed = perform_cleaning(selected, candidates, move_to_quarantine=move_to_quarantine)

    print("\n--- Cleaning Results ---")
    for t, src, dest in done:
        if t == "moved":
            print(f"✅ Moved: {src} -> {dest}")
        else:
            print(f"✅ Deleted: {src}")
    if failed:
        print("\n⚠️ Failed to remove some files:")
        for path, err in failed:
            print(f" - {path} ({err})")

    reclaimed = 0
    for t, src, dest in done:
        try:
            for c in candidates:
                if c['path'] == src:
                    reclaimed += c.get('size', 0)
                    break
        except Exception:
            continue

    print(f"\nCleaning complete. Estimated reclaimed space: {human_size(reclaimed)}")
    print("If files were moved, check the quarantine folder to restore if needed.")

# =====================================================
# 🔒 System Lockdown
# =====================================================
def _lockdown_window_impl(minutes):
    end_time = datetime.now() + timedelta(minutes=minutes)

    win = tk.Toplevel(root)
    win.title("🛡️ GhostWall Lockdown Active")
    win.configure(bg="black")
    win.attributes("-fullscreen", True)
    win.attributes("-topmost", True)
    win.focus_force()
    win.grab_set()

    msg = tk.Label(
        win,
        text=f"⚠️ SYSTEM LOCKDOWN ACTIVE ⚠️\n\n"
             f"Access is temporarily restricted.\n\n"
             f"Lockdown ends at: {end_time.strftime('%H:%M:%S')}",
        font=("Segoe UI", 24, "bold"),
        fg="red",
        bg="black",
        justify="center"
    )
    msg.pack(expand=True)

    stop_lockdown = threading.Event()

    def end_lockdown():
        if messagebox.askyesno("End Lockdown", "Are you sure you want to end lockdown early?", parent=win):
            stop_lockdown.set()
            try:
                win.destroy()
            except:
                pass

    btn = tk.Button(
        win,
        text="End Lockdown Early",
        command=end_lockdown,
        font=("Segoe UI", 16, "bold"),
        bg="gray20",
        fg="white",
        relief="ridge",
        width=22
    )
    btn.pack(pady=50)

    def countdown():
        while not stop_lockdown.is_set():
            remaining = (end_time - datetime.now()).total_seconds()
            if remaining <= 0:
                try:
                    popup_info("Lockdown period ended. You may resume normal activity.", "Lockdown Complete")
                    stop_lockdown.set()
                    try:
                        win.destroy()
                    except:
                        pass
                except:
                    pass
                break
            mins_left = int(remaining // 60)
            secs_left = int(remaining % 60)
            try:
                msg.config(
                    text=f"⚠️ SYSTEM LOCKDOWN ACTIVE ⚠️\n\n"
                         f"Access restricted for security reasons.\n\n"
                         f"Time remaining: {mins_left:02d}:{secs_left:02d}\n\n"
                         f"Lockdown ends at: {end_time.strftime('%H:%M:%S')}"
                )
            except tk.TclError:
                break
            time.sleep(1)

    threading.Thread(target=countdown, daemon=True).start()

def system_lockdown():
    print("\n=== 🔒 System Lockdown Mode ===")
    mins = ask_lockdown_minutes_popup()

    if mins is None:
        try:
            mins = float(input("Enter lockdown duration (in minutes): ").strip())
        except Exception:
            print("❌ Invalid input. Returning.")
        return

    # GUI window in main thread
    run_in_gui_thread(_lockdown_window_impl, mins)

# =====================================================
# 🩹 Patch Monitor
# =====================================================
def _try_parse_date(s):
    if not s:
        return None
    s = s.strip()
    s = s.split("T")[0] if "T" in s and "-" in s else s
    candidates = [
        "%m/%d/%Y",
        "%m/%d/%Y %I:%M:%S %p",
        "%d/%m/%Y",
        "%d/%m/%Y %H:%M:%S",
        "%Y-%m-%d",
        "%Y-%m-%d %H:%M:%S",
        "%d-%b-%Y",
        "%b %d %Y",
        "%d %b %Y",
    ]
    for fmt in candidates:
        try:
            return datetime.strptime(s, fmt)
        except Exception:
            continue
    try:
        if len(s) >= 8 and s.isdigit():
            return datetime.strptime(s[:8], "%Y%m%d")
    except Exception:
        pass
    return None

def get_patch_status():
    """
    Reliable Windows patch status detection (NO DATES REQUIRED).
    Returns (status, message)
    """
    if os.name != "nt":
        return "unsupported", "Patch Monitor supports Windows only."

    try:
        # Check Windows Update service
        cmd = [
            "powershell",
            "-NoProfile",
            "-Command",
            "(Get-Service wuauserv).Status"
        ]
        service_status = subprocess.check_output(
            cmd, stderr=subprocess.DEVNULL
        ).decode(errors="ignore").strip()

        if service_status.lower() != "running":
            return "warning", "Windows Update service is not running."

        # Check last successful update scan
        cmd = [
            "powershell",
            "-NoProfile",
            "-Command",
            "(New-Object -ComObject Microsoft.Update.AutoUpdate).Results.LastSearchSuccessDate"
        ]
        out = subprocess.check_output(
            cmd, stderr=subprocess.DEVNULL
        ).decode(errors="ignore").strip()

        if out:
            dt = _try_parse_date(out)
            if dt:
                age = (datetime.now() - dt).days
                return "ok", f"Windows Update scan successful {age} days ago."

        return "info", "Windows Update is active, but history is unavailable."

    except Exception:
        return "info", "Unable to determine detailed patch history."


def get_latest_patch_date():
    """
    Enterprise-grade Windows patch detection using Event Logs.
    This works even when Get-HotFix / CIM / Registry fail.
    """
    if os.name != "nt":
        return None

    try:
        cmd = [
            "powershell",
            "-NoProfile",
            "-Command",
            r"""
            $events = Get-WinEvent -LogName 'Microsoft-Windows-WindowsUpdateClient/Operational' `
                -FilterXPath "*[System[(EventID=19)]]" `
                -MaxEvents 1
            if ($events) {
                $events.TimeCreated
            }
            """
        ]

        out = subprocess.check_output(
            cmd,
            stderr=subprocess.DEVNULL,
            shell=False
        ).decode(errors="ignore").strip()

        return _try_parse_date(out)

    except Exception:
        return None



def patch_monitor(threshold_days=30, show_popup=True):
    print("\n=== 🩹 Patch Monitor ===")

    status, msg = get_patch_status()

    print(msg)

    if show_popup:
        if status == "ok":
            popup_info(msg, "Patch Monitor")
        elif status == "warning":
            popup_warning(msg, "Patch Monitor")
        else:
            popup_info(msg, "Patch Monitor")


# =====================================================
# 🔐 Password Vault
# =====================================================
def save_password():
    try:
        os.makedirs(PASS_DIR, exist_ok=True)
        where = input("🔹 Enter where this password is used (e.g. Gmail, Netflix): ").strip()
        passwd = input("🔹 Enter the password: ").strip()
        if not where or not passwd:
            print("❌ Fields cannot be empty!")
            return

        enc = _encrypt_text(passwd, MASTER_PASSWORD)
        safe_name = "".join(c for c in where if c.isalnum() or c in ("_", "-"))
        filename = f"{safe_name}_{int(time.time())}.bin"
        full_path = os.path.join(PASS_DIR, filename)

        with open(full_path, "wb") as f:
            f.write(enc)
        print(f"✅ Password saved securely at: {full_path}")

    except Exception as e:
        print(f"⚠️ Error saving password: {e}")

def show_password():
    try:
        master = input("🔐 Enter master password: ").strip()
        if master != MASTER_PASSWORD:
            print("❌ Incorrect master password! Returning to main menu...")
            return

        if not os.path.exists(PASS_DIR) or not os.listdir(PASS_DIR):
            print("📂 No saved passwords found.")
            return

        files = os.listdir(PASS_DIR)
        print("\nSaved passwords:")
        for i, f in enumerate(files, start=1):
            print(f" {i}. {f}")
        try:
            choice = int(input("\nSelect a password file number to view: "))
            if choice < 1 or choice > len(files):
                print("❌ Invalid selection.")
                return
            file_path = os.path.join(PASS_DIR, files[choice - 1])
            with open(file_path, "rb") as f:
                enc = f.read()
            decrypted = _decrypt_text(enc, MASTER_PASSWORD)
            print(f"\n🔓 Password for {files[choice - 1]}: {decrypted}\n")
        except ValueError:
            print("❌ Invalid input.")
        except Exception as e:
            print(f"⚠️ Error reading file: {e}")

    except Exception as e:
        print(f"⚠️ Error: {e}")

def manage_saved_entry():
    try:
        if not os.path.exists(PASS_DIR) or not os.listdir(PASS_DIR):
            print("📂 No saved passwords found.")
            return

        files = os.listdir(PASS_DIR)
        print("\nSaved password files:")
        for i, f in enumerate(files, start=1):
            print(f" {i}. {f}")

        ch = input("\nEnter number of entry to manage (or 0 to cancel): ").strip()
        if ch == "0":
            return

        try:
            index = int(ch)
            if index < 1 or index > len(files):
                print("❌ Invalid selection.")
                return
            file_path = os.path.join(PASS_DIR, files[index - 1])

            print("\n1️⃣  Delete entry")
            print("2️⃣  Rename entry")
            print("3️⃣  Cancel")
            opt = input("Choose option: ").strip()

            if opt == "1":
                os.remove(file_path)
                print("🗑️ Entry deleted successfully.")
            elif opt == "2":
                new_name = input("Enter new name (no extension): ").strip()
                if not new_name:
                    print("❌ Name cannot be empty.")
                    return
                safe_name = "".join(c for c in new_name if c.isalnum() or c in ("_", "-"))
                new_path = os.path.join(PASS_DIR, safe_name + ".bin")
                os.rename(file_path, new_path)
                print(f"✅ Entry renamed to: {safe_name}.bin")
            else:
                print("↩️ Cancelled.")
        except ValueError:
            print("❌ Invalid input.")
    except Exception as e:
        print(f"⚠️ Error managing entry: {e}")

def change_master_password():
    global MASTER_PASSWORD
    try:
        current = input("Enter current master password: ").strip()
        if current != MASTER_PASSWORD:
            print("❌ Incorrect current password.")
            return

        new_pass = input("Enter new master password: ").strip()
        confirm = input("Confirm new master password: ").strip()

        if new_pass != confirm or not new_pass:
            print("❌ Passwords do not match or are empty.")
            return

        if os.path.exists(PASS_DIR):
            for fname in os.listdir(PASS_DIR):
                path = os.path.join(PASS_DIR, fname)
                with open(path, "rb") as f:
                    enc = f.read()
                plain = _decrypt_text(enc, MASTER_PASSWORD)
                new_enc = _encrypt_text(plain, new_pass)
                with open(path, "wb") as f:
                    f.write(new_enc)

        MASTER_PASSWORD = new_pass
        print("✅ Master password changed and all entries re-encrypted successfully.")

    except Exception as e:
        print(f"⚠️ Error changing password: {e}")

def password_vault():
    while True:
        print("\n=== 🔐 PASSWORD VAULT ===")
        print("1️⃣  Save a new password")
        print("2️⃣  Show saved passwords")
        print("3️⃣  Manage saved entries (Delete / Rename)")
        print("4️⃣  Change master password")
        print("5️⃣  Back to main menu")
        ch = input("Enter choice: ").strip()

        if ch == "1":
            save_password()
        elif ch == "2":
            show_password()
        elif ch == "3":
            manage_saved_entry()
        elif ch == "4":
            change_master_password()
        elif ch == "5":
            break
        else:
            print("❌ Invalid choice, try again.")

# =====================================================
# 🧩 MAIN MENU (console, runs in its own thread)
# =====================================================
def main_menu():
    if not is_admin():
        show_admin_warning()

    signatures = load_signatures()

    while True:
        print("\n===============================")
        print("🛡️  GHOSTWALL ANTIVIRUS TOOLKIT")
        print("===============================")
        print("1️⃣  Malware Scanner")
        print("2️⃣  File Locker (Encrypt/Decrypt)")
        print("3️⃣  Firewall")
        print("4️⃣  USB Scanner (Always On)")
        print("5️⃣  System Cleaner")
        print("6️⃣  System Lockdown (NEW)")
        print("7️⃣  Patch Monitor (NEW)")
        print("8️⃣  Password Vault (NEW)")
        print("9️⃣  Exit")
        print("===============================")

        choice = input("Enter your choice (1-9): ").strip()

        if choice == "1":
            print("\n1️⃣ Malware Scanner Options:")
            print("   a) Full System Scan")
            print("   b) Folder Scan")
            sub = input("Select option (a/b): ").strip().lower()
            if sub == "a":
                scan_system(signatures)
            elif sub == "b":
                folder = input("Enter folder path to scan: ").strip()
                if os.path.exists(folder):
                    scan_folder(folder, signatures)
                else:
                    print("❌ Folder not found.")
            else:
                print("Invalid option.")
        elif choice == "2":
            print("\n2️⃣ File Locker Options:")
            print("   a) Encrypt File")
            print("   b) Decrypt File")
            sub = input("Select option (a/b): ").strip().lower()
            if sub == "a":
                encrypt_file()
            elif sub == "b":
                decrypt_file()
            else:
                print("Invalid option.")
        elif choice == "3":
            firewall()
        elif choice == "4":
            print("💽 USB Scanner is always running in the background.")
        elif choice == "5":
            system_cleaner_menu()
        elif choice == "6":
            system_lockdown()
        elif choice == "7":
            days = ask_patch_days_popup(default=30)

            if days is None:
                try:
                    inp = input("Enter threshold in days to consider 'outdated' [default 30]: ").strip()
                    days = int(inp) if inp else 30
                except Exception:
                    days = 30
            patch_monitor(threshold_days=days, show_popup=True)

        elif choice == "8":
            print("Entering the PASSWORD VAULT !!")
            password_vault()
        elif choice == "9":
            print("👋 Exiting GhostWall. Stay protected!")
            time.sleep(1)
            os._exit(0)
        else:
            print("❌ Invalid input. Please choose between 1–9.")

def safe_tk_cleanup():
    try:
        tk._default_root = None
    except:
        pass

atexit.register(safe_tk_cleanup)

# =====================================================
# Entry Point
# =====================================================
if __name__ == "__main__":
    # Start processing GUI call queue in the GUI (main) thread
    _process_gui_calls()

    # Start background threads: USB monitor + console menu
    threading.Thread(target=usb_scanner_background, daemon=True).start()
    threading.Thread(target=main_menu, daemon=True).start()

    # Start Tk mainloop (handles USB password popup & other dialogs)
    root.mainloop()
