import time
import json
import requests
import pyperclip
import evdev
from evdev import InputDevice, categorize, ecodes
import threading
import subprocess
import os
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import signal
import shutil


# Server and User Information
SERVER_URL = "http://192.168.1.100:5000"
LOG_ENDPOINT = f"{SERVER_URL}/log"
# Endpoints for the separate CSV files:
MALICIOUS_ENDPOINT = f"{SERVER_URL}/malicious"
MERGED_ENDPOINT = f"{SERVER_URL}/merged"
RM_ENDPOINT = f"{SERVER_URL}/rm"
USER = "BranchPC-1"

#file monitoring
BACKUP_DIR="/tmp/file_monitor_backup/"

# Global dictionary to store command categories fetched from the server
command_categories = {
    "malicious": set(),  # e.g. command_injection.csv
    "merged": set(),     # e.g. merged_malicious_commands.csv
    "rm": set()          # e.g. rm_commands.csv
}

def fetch_commands(endpoint):
    """Fetch commands from a given endpoint and return them as a set (in lowercase)."""
    try:
        response = requests.get(endpoint)
        if response.status_code == 200:
            commands = response.json().get("commands", [])
            return set(cmd.lower() for cmd in commands)
        else:
            print(f"Failed to fetch commands from {endpoint}. Status:", response.status_code)
            return set()
    except Exception as e:
        print(f"Error fetching commands from {endpoint}: {e}")
        return set()

def fetch_all_commands():
    """Fetch commands from all three endpoints and update the global dictionary."""
    global command_categories
    command_categories["malicious"] = fetch_commands(MALICIOUS_ENDPOINT)
    command_categories["merged"] = fetch_commands(MERGED_ENDPOINT)
    command_categories["rm"] = fetch_commands(RM_ENDPOINT)
    print("Fetched command categories:")
    for category, cmds in command_categories.items():
        print(f"  {category}: {len(cmds)} commands")

def send_log(event_type, data, timestamp):
    payload = {"user": USER, "event_type": event_type, "data": data, "timestamp": timestamp}
    try:
        requests.post(LOG_ENDPOINT, json=payload)
    except Exception as e:
        print(f"Failed to send log: {e}")

# File Monitoring Handler (unchanged)
class FileMonitorHandler(FileSystemEventHandler):

    def __init__(self, directories):

        self.directories = directories

        self.file_hashes = {}

        self.initialize_hashes()



    def initialize_hashes(self):

        for directory in self.directories:

            for root, _, files in os.walk(directory):

                for file in files:

                    file_path = os.path.join(root, file)

                    self.file_hashes[file_path] = self.hash_file(file_path)



    def hash_file(self, file_path):

        try:

            with open(file_path, 'rb') as f:

                return hashlib.md5(f.read()).hexdigest()

        except Exception as e:

            return None



    def on_created(self, event):

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        if event.is_directory:

        

            send_log(f"Directory created: {event.src_path}",event.src_path,timestamp)

        else:

          if not os.path.basename(event.src_path).startswith('.'):

            send_log(f"File created: {event.src_path}",event.src_path,timestamp)

            self.file_hashes[event.src_path] = self.hash_file(event.src_path)



    def on_deleted(self, event):

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        send_log(f"Deleted: {event.src_path}",event.src_path,timestamp)

        self.file_hashes.pop(event.src_path, None)

 

    def on_opened(self, event):

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        if not os.path.basename(event.src_path).startswith('.'):

         send_log(f"File opened: {event.src_path}",event.src_path,timestamp)

        



def start_monitoring(directories):

    event_handler = FileMonitorHandler(directories)

    observer = Observer()

    for directory in directories:

        observer.schedule(event_handler, directory, recursive=True)

    observer.start()

    try:

        while True:

            time.sleep(1)

    except KeyboardInterrupt:

        observer.stop()

    observer.join()



def monitor_files(paths):

  os.makedirs(BACKUP_DIR, exist_ok=True)

  file_mtime_cache= {path: os.stat(path).st_mtime for path in paths}

  

  for path in paths:

     try:

       file_mtime_cache[path]=os.stat(path).st_mtime

       shutil.copy2(path, os.path.join(BACKUP_DIR, os.path.basename(path)))

     except FileNotFoundError:

       pass

  

  while True:

    for path in paths:

      try:

       current_mtime=os.stat(path).st_mtime

       if current_mtime != file_mtime_cache[path]:

          print(f"Modified file: {path}")

          

          backup_file=os.path.join(BACKUP_DIR, os.path.basename(path))

          diff_output=subprocess.run(["diff","-u", backup_file,path], capture_output=True, text=True)

          

          diff_output_list=diff_output.stdout.splitlines()

          added_line= next((line for line in reversed(diff_output_list) if line.startswith('+')), None)

          removed_line= next((line for line in reversed(diff_output_list) if line.startswith('-')), None)

          changes=''

          if added_line:

            changes+=added_line+'\n'

          if removed_line:

            changes+=removed_line

          

          if changes:

            send_log("file modified",f"{path}:{changes}",current_mtime)

          else:

            print("no difference")  

            

            

          

          shutil.copy2(path, backup_file)

          file_mtime_cache[path]=current_mtime

      except FileNotFoundError:

        pass

    time.sleep(1)

# Monitor active applications
def monitor_apps():
    tracked_apps = ["soffice", "winword.exe"]
    while True:
        for proc in psutil.process_iter(attrs=['pid', 'name']):
            if any(app in proc.info['name'].lower() for app in tracked_apps):
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                send_log("Application Launched", proc.info['name'], timestamp)
        time.sleep(5)

# Monitor clipboard
def monitor_clipboard():
    previous_clipboard = ""
    while True:
        try:
            current_clipboard = pyperclip.paste()
            if current_clipboard != previous_clipboard:
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                send_log("Clipboard", current_clipboard, timestamp)
                previous_clipboard = current_clipboard
        except Exception as e:
            print(f"Error monitoring clipboard: {e}")
        time.sleep(2)

# Instead of killing the system, close only the active window
def close_active_window():
    try:
        subprocess.run(["xdotool", "getactivewindow", "windowclose"], check=True)
        print("Closed the active window due to malicious command.")
    except Exception as e:
        print(f"Error closing active window: {e}")

def check_malicious_command(buffer):
    """
    Check if any command from any category is present in the buffer.
    Returns a tuple: (detected: bool, category: str or None)
    """
    buffer_lower = buffer.lower()
    for category, commands in command_categories.items():
        for cmd in commands:
            if cmd in buffer_lower:
                print(f"Detected '{cmd}' from category '{category}' in buffer.")
                return True, category
    return False, None
# Keylogger using evdev (modified for auto-detection)
typed_string = ""
last_keypress_time = time.time()

def handle_detected_command(typed_string):
    detected, category = check_malicious_command(typed_string)
    if detected:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        # Close the active window regardless of category
        print(f"Potential malicious command detected from category '{category}': {typed_string}")
        close_active_window()

        # Log the event with the correct category
        event_type = f"Malicious Command {category.capitalize()}"
        send_log(event_type, f"Potential malicious command detected from category '{category}': {typed_string}", timestamp)

        return True
    return False
    
def monitor_keyboard():
    global typed_string, last_keypress_time

    # Simplified keycode-to-character mapping
    key_to_char = {
        'space': ' ', 'slash': '/', 'dot': '.', 'minus': '-', 'equal': '=', 'comma': ',',
        'period': '.', 'semicolon': ';', 'apostrophe': "'", 'bracketleft': '[',
        'bracketright': ']', 'backslash': '\\', 'grave': '', 'enter': '\n',
        'tab': '\t', '1': '1', '2': '2', '3': '3', '4': '4', '5': '5',
        '6': '6', '7': '7', '8': '8', '9': '9', '0': '0',
    }
"""key_to_char = {
        'space': ' ',
        'kpslash': '/', 
        'minus': '-', 
        'equal': '=', 
        'comma': ',',
        'kpdot': '.', 
        'semicolon': ';', 
        'apostrophe': "'", 
        'bracketleft': '[',
        'bracketright': ']', 
        'backslash': '\', 
        'grave': '`', 
        'enter': '\n',
        'tab': '\t',
        'kp1': '1', 'kp2': '2', 'kp3': '3', 'kp4': '4', 'kp5': '5',
        'kp6': '6', 'kp7': '7', 'kp8': '8', 'kp9': '9', 'kp0': '0',
    }"""

    devices = [InputDevice(path) for path in evdev.list_devices()]
    keyboard = None
    for device in devices:
        if "keyboard" in device.name.lower():
            keyboard = device
            break

    if not keyboard:
        print("No keyboard found.")
        return

    for event in keyboard.read_loop():
        if event.type == ecodes.EV_KEY:
            key_event = categorize(event)
            if key_event.keystate == key_event.key_down:
                key_name = ecodes.KEY.get(event.code, event.code)
                if isinstance(key_name, int):
                    key_name = str(key_name)
                if key_name.startswith("KEY_"):
                    key_name = key_name[4:].lower()

                char = key_to_char.get(key_name, key_name)

                if char == '\n':
                    if typed_string:
                        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                        send_log("Typed String", typed_string, timestamp)
                        handle_detected_command(typed_string)
                        typed_string = ""
                else:
                    typed_string += char
                    last_keypress_time = time.time()
                    # Check for malicious commands on-the-fly
                    if handle_detected_command(typed_string):
                        # Optionally, clear the typed string if a malicious pattern is detected
                        typed_string = ""
                # Optionally log each key press
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                send_log("Key Pressed", char, timestamp)

        # Auto-send buffer if inactive for 2 seconds
        if time.time() - last_keypress_time > 2 and typed_string:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            send_log("Typed String", typed_string, timestamp)
            handle_detected_command(typed_string)
            typed_string = ""

# Monitor active window
def monitor_active_window():
    previous_window = ""
    while True:
        result = subprocess.run(["xdotool", "getactivewindow", "getwindowname"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        current_window = result.stdout.strip() if result.returncode == 0 else "No active window"
        if current_window != previous_window:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            send_log("Active Window", current_window, timestamp)
            previous_window = current_window
        time.sleep(5)

#monitor_files
    
def continues_monitoring(path, path_to_monitor,dir_path):

      for filename in os.listdir(path):

       full_path=os.path.join(path,filename)

       if not os.path.isdir(full_path):

        paths_to_monitor.append(full_path)

       else:

        dir_path.append(full_path)

        continues_monitoring(full_path,path_to_monitor,dir_path)

if __name__ == "__main__":
    # Fetch the commands from the server at startup.
    fetch_all_commands()

    paths_to_monitor = ["/etc/passwd","/etc/shadow","/etc/group","/etc/sudoers","/etc/hosts","/var/log/auth.log","/var/log/syslog","/boot/grub/grub.cfg"]

    directories_to_monitor=["/home/abdalhadi/Downloads/","/home/abdalhadi/Documents","/home/abdalhadi/.ssh","/mnt","/media","/tmp"]
    
    continues_monitoring("/home/abdalhadi/Downloads",paths_to_monitor,directories_to_monitor)

    continues_monitoring("/home/abdalhadi/Documents",paths_to_monitor,directories_to_monitor)

    continues_monitoring("/mnt",paths_to_monitor,directories_to_monitor)

    continues_monitoring("/home/abdalhadi/.ssh",paths_to_monitor,directories_to_monitor)

    


    clipboard_thread = threading.Thread(target=monitor_clipboard, daemon=True)
    active_window_thread = threading.Thread(target=monitor_active_window, daemon=True)
    app_monitor_thread = threading.Thread(target=monitor_apps, daemon=True)
    file_monitor_thread = threading.Thread(target=monitor_files, args=(paths_to_monitor,), daemon=True)
    keyboard_thread = threading.Thread(target=monitor_keyboard, daemon=True)

    clipboard_thread.start()
    active_window_thread.start()
    app_monitor_thread.start()
    file_monitor_thread.start()
    dir_monitor_thread.start()
    keyboard_thread.start()

    clipboard_thread.join()
    active_window_thread.join()
    app_monitor_thread.join()
    file_monitor_thread.join()
    dir_monitor_thread.join()
    keyboard_thread.join()
