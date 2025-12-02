import time
import subprocess
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


WATCH_DIR = "/home/shubham"


# ------------------ FILE MONITORING ------------------
class FileHandler(FileSystemEventHandler):
    def on_created(self, event):
        print(f"📁 Created: {event.src_path}")

    def on_deleted(self, event):
        print(f"🗑 Deleted: {event.src_path}")

    def on_modified(self, event):
        print(f"✏️ Modified: {event.src_path}")

    def on_moved(self, event):
        print(f"📥 Moved: {event.src_path} → {event.dest_path}")


def monitor_files():
    event_handler = FileHandler()
    observer = Observer()
    observer.schedule(event_handler, WATCH_DIR, recursive=True)
    observer.start()

    print(f"📂 Monitoring directory: {WATCH_DIR}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()


# ------------------ AUTH LOG MONITORING ------------------
def monitor_auth_log():
    print("🔐 Monitoring ALL authentication logs… (journalctl -f)")
    
    process = subprocess.Popen(
        ["journalctl", "-f", "-o", "cat"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    for line in process.stdout:
        line = line.strip()

        # Authentication failures
        if "authentication failure" in line.lower():
            print(f"❌ Authentication Failure: {line}")

        if "failed password" in line.lower():
            print(f"🔐 Failed Password Attempt: {line}")

        # Sudo incorrect password
        # if "incorrect password" in line.lower():
        #     print(f"❌ Wrong sudo password: {line}")

        # # Root login
        # if "session opened for user root" in line.lower():
        #     print(f"⚠️ Root session opened: {line}")

        # Any sudo activity
        if "sudo" in line.lower() and "tty" in line.lower():
            print(f"🟡 Sudo Attempt: {line}")


# ------------------ RUN BOTH ------------------
if __name__ == "__main__":
    import threading

    print("🔒 Starting Linux Security Logger (Files + Auth Logs)")

    # Thread 1 → Auth logs
    t1 = threading.Thread(target=monitor_auth_log, daemon=True)
    t1.start()

    # Thread 2 → File system
    monitor_files()

