import time
import subprocess
import os
import logging
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


WATCH_DIR = r"C:\Users\kunal\OneDrive\Desktop"
LOG_FILE = "security_events.log"

# Configure logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='[%(asctime)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)


def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log_event(message):
    """Log event to both console and file"""
    print(message)
    logging.info(message.replace('[', '').replace(']', '', 1))


# ------------------ FILE MONITORING ------------------
class FileHandler(FileSystemEventHandler):
    def on_created(self, event):
        log_event(f"[{timestamp()}] 📁 Created: {event.src_path}")

    # def on_deleted(self, event):
    #     log_event(f"[{timestamp()}] 🗑 Deleted: {event.src_path}")

    # def on_modified(self, event):
    #     log_event(f"[{timestamp()}] ✏️ Modified: {event.src_path}")

    def on_moved(self, event):
        log_event(f"[{timestamp()}] 📥 Moved: {event.src_path} → {event.dest_path}")


def monitor_files():
    event_handler = FileHandler()
    observer = Observer()
    observer.schedule(event_handler, WATCH_DIR, recursive=True)
    observer.start()

    log_event(f"[{timestamp()}] 📂 Monitoring directory: {WATCH_DIR}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log_event(f"[{timestamp()}] ⏹️ Stopping file monitor...")
        observer.stop()
    except Exception as e:
        log_event(f"[{timestamp()}] ❌ Error in file monitoring: {e}")
        observer.stop()
    finally:
        observer.join()


# ------------------ AUTH LOG MONITORING ------------------
def monitor_auth_log():
    log_event(f"[{timestamp()}] 🔐 Monitoring ALL authentication logs… (journalctl -f)")
    
    try:
        process = subprocess.Popen(
            ["journalctl", "-f", "-o", "cat"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
    except FileNotFoundError:
        log_event(f"[{timestamp()}] ⚠️ journalctl not available (Windows system detected)")
        return

    try:
        for line in process.stdout:
            line = line.strip()

            # Authentication failures
            if "authentication failure" in line.lower():
                log_event(f"[{timestamp()}] ❌ Authentication Failure: {line}")

            if "failed password" in line.lower():
                log_event(f"[{timestamp()}] 🔐 Failed Password Attempt: {line}")

            # Sudo incorrect password
            if "incorrect password" in line.lower():
                log_event(f"[{timestamp()}] ❌ Wrong sudo password: {line}")

            # Root login
            if "session opened for user root" in line.lower():
                log_event(f"[{timestamp()}] ⚠️ Root session opened: {line}")

            # Any sudo activity
            if "sudo" in line.lower() and "tty" in line.lower():
                log_event(f"[{timestamp()}] 🟡 Sudo Attempt: {line}")
    except KeyboardInterrupt:
        log_event(f"[{timestamp()}] ⏹️ Stopping auth log monitor...")
        process.terminate()


# ------------------ RUN BOTH ------------------
if __name__ == "__main__":
    import threading

    log_event(f"[{timestamp()}] 🔒 Starting Linux Security Logger (Files + Auth Logs)")
    log_event(f"[{timestamp()}] 📝 Logging to: {os.path.abspath(LOG_FILE)}")
    print("Press Ctrl+C to stop monitoring...\n")

    try:
        #Thread 1 → Auth logs
        t1 = threading.Thread(target=monitor_auth_log, daemon=True)
        t1.start()

        # Thread 2 → File system
        monitor_files()
    except KeyboardInterrupt:
        log_event(f"\n[{timestamp()}] 🛑 Security Logger stopped.")
    except Exception as e:
        log_event(f"[{timestamp()}] 💥 Unexpected error: {e}")

