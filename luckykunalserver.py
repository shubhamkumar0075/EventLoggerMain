import time
import subprocess
import os
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


WATCH_DIR = r"C:\Users\kunal\OneDrive\Desktop"


def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ------------------ FILE MONITORING ------------------
class FileHandler(FileSystemEventHandler):
    def on_created(self, event):
        print(f"[{timestamp()}] 📁 Created: {event.src_path}")

    # def on_deleted(self, event):
    #     print(f"[{timestamp()}] 🗑 Deleted: {event.src_path}")

    # def on_modified(self, event):
    #     print(f"[{timestamp()}] ✏️ Modified: {event.src_path}")

    def on_moved(self, event):
        print(f"[{timestamp()}] 📥 Moved: {event.src_path} → {event.dest_path}")


def monitor_files():
    event_handler = FileHandler()
    observer = Observer()
    observer.schedule(event_handler, WATCH_DIR, recursive=True)
    observer.start()

    print(f"[{timestamp()}] 📂 Monitoring directory: {WATCH_DIR}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"[{timestamp()}] ⏹️ Stopping file monitor...")
        observer.stop()
    except Exception as e:
        print(f"[{timestamp()}] ❌ Error in file monitoring: {e}")
        observer.stop()
    finally:
        observer.join()


# ------------------ AUTH LOG MONITORING ------------------
def monitor_auth_log():
    print(f"[{timestamp()}] 🔐 Monitoring ALL authentication logs… (journalctl -f)")
    
    try:
        process = subprocess.Popen(
            ["journalctl", "-f", "-o", "cat"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
    except FileNotFoundError:
        print(f"[{timestamp()}] ⚠️ journalctl not available (Windows system detected)")
        return

    try:
        for line in process.stdout:
            line = line.strip()

            # Authentication failures
            if "authentication failure" in line.lower():
                print(f"[{timestamp()}] ❌ Authentication Failure: {line}")

            if "failed password" in line.lower():
                print(f"[{timestamp()}] 🔐 Failed Password Attempt: {line}")

            # Sudo incorrect password
            if "incorrect password" in line.lower():
                print(f"[{timestamp()}] ❌ Wrong sudo password: {line}")

            # Root login
            if "session opened for user root" in line.lower():
                print(f"[{timestamp()}] ⚠️ Root session opened: {line}")

            # Any sudo activity
            if "sudo" in line.lower() and "tty" in line.lower():
                print(f"[{timestamp()}] 🟡 Sudo Attempt: {line}")
    except KeyboardInterrupt:
        print(f"[{timestamp()}] ⏹️ Stopping auth log monitor...")
        process.terminate()


# ------------------ RUN BOTH ------------------
if __name__ == "__main__":
    import threading

    print(f"[{timestamp()}] 🔒 Starting Linux Security Logger (Files + Auth Logs)")
    print("Press Ctrl+C to stop monitoring...\n")

    try:
        #Thread 1 → Auth logs
        t1 = threading.Thread(target=monitor_auth_log, daemon=True)
        t1.start()

        # Thread 2 → File system
        monitor_files()
    except KeyboardInterrupt:
        print(f"\n[{timestamp()}] 🛑 Security Logger stopped.")
    except Exception as e:
        print(f"[{timestamp()}] 💥 Unexpected error: {e}")

