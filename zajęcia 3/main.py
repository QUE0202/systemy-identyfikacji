import hashlib
import os
import pyotp
import base64
import qrcode
import time
from pynput import keyboard, mouse


class BehaviorMonitor:
    def __init__(self):
        self.key_timings = []
        self.mouse_movements = []
        self.last_key_time = None
        self.last_mouse_time = None

    def on_key_press(self, key):
        current_time = time.time()
        if self.last_key_time is not None:
            self.key_timings.append(current_time - self.last_key_time)
        self.last_key_time = current_time

    def on_mouse_move(self, x, y):
        current_time = time.time()
        if self.last_mouse_time is not None:
            self.mouse_movements.append(current_time - self.last_mouse_time)
        self.last_mouse_time = current_time

    def start_monitoring(self):
        self.key_timings = []
        self.mouse_movements = []
        self.last_key_time = None
        self.last_mouse_time = None
        keyboard_listener = keyboard.Listener(on_press=self.on_key_press)
        mouse_listener = mouse.Listener(on_move=self.on_mouse_move)
        keyboard_listener.start()
        mouse_listener.start()
        return keyboard_listener, mouse_listener

    def stop_monitoring(self, keyboard_listener, mouse_listener):
        keyboard_listener.stop()
        mouse_listener.stop()

    def get_behavioral_data(self):
        return {
            "key_timings": self.key_timings if self.key_timings else [0],
            "mouse_movements": self.mouse_movements if self.mouse_movements else [0]
        }


behavior_monitor = BehaviorMonitor()
users = {}


def save_users(users, filename="users.txt"):
    with open(filename, "w") as f:
        for username, user_data in users.items():
            timestamp = user_data.get("timestamp", 0)
            key_timings = ",".join([str(k) for k in user_data["behavior"]["key_timings"]]) if user_data["behavior"] else ""
            mouse_movements = ",".join([str(m) for m in user_data["behavior"]["mouse_movements"]]) if user_data["behavior"] else ""
            behavior_data = f"{key_timings}|{mouse_movements}"
            f.write(f"{username}:{user_data['password']}:{timestamp}:{user_data['secret']}:{behavior_data}\n")


def load_users(filename="users.txt"):
    global users
    if os.path.exists(filename):
        with open(filename, "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 5:
                    username = parts[0]
                    hashed_password = parts[1]
                    timestamp = float(parts[2])
                    secret = parts[3]
                    behavior_part = parts[4]
                    if "|" in behavior_part:
                        key_data, mouse_data = behavior_part.split("|")
                        key_timings = [float(k) for k in key_data.split(",")] if key_data else []
                        mouse_movements = [float(m) for m in mouse_data.split(",")] if mouse_data else []
                        behavior = {"key_timings": key_timings, "mouse_movements": mouse_movements}
                    else:
                        behavior = None
                    users[username] = {
                        "password": hashed_password,
                        "timestamp": timestamp,
                        "secret": secret,
                        "behavior": behavior
                    }


load_users()


def analyze_behavior(username, behavioral_data):
    stored_data = users.get(username, {}).get("behavior", None)
    if not stored_data:
        return True

    key_timings_sum = sum(stored_data["key_timings"])
    mouse_movements_sum = sum(stored_data["mouse_movements"])

    key_diff = abs(key_timings_sum - sum(behavioral_data["key_timings"]))
    mouse_diff = abs(mouse_movements_sum - sum(behavioral_data["mouse_movements"]))

    tolerance = 5
    return key_diff < tolerance and mouse_diff < tolerance


def enable_2fa(username):
    secret = base64.b32encode(os.urandom(16)).decode('utf-8')
    users[username]["secret"] = secret
    save_users(users)
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username)
    print(f"\n2FA Secret: {secret}")
    print("Scan this QR code with Google Authenticator or similar app:")
    qr = qrcode.make(uri)
    qr.show()


def verify_2fa(username):
    user_data = users.get(username)
    if not user_data or not user_data.get("secret"):
        return False
    secret = user_data["secret"]
    totp = pyotp.TOTP(secret)
    code = input("Enter the code from Google Authenticator: ")
    return totp.verify(code)


def register():
    username = input("Username: ")
    password = input("Password: ")

    if username in users:
        print("Username already exists.")
        return

    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    timestamp = time.time()
    users[username] = {"password": hashed_password, "timestamp": timestamp, "secret": None, "behavior": None}

    keyboard_listener, mouse_listener = behavior_monitor.start_monitoring()
    print("Type your password again to record behavioral data...")
    input("Password: ")
    behavior_monitor.stop_monitoring(keyboard_listener, mouse_listener)

    users[username]["behavior"] = behavior_monitor.get_behavioral_data()
    save_users(users)
    print("Registration successful!")
    enable_2fa(username)


def login():
    username = input("Username: ")
    attempts = 3
    while attempts > 0:
        password = input("Password: ")
        user_data = users.get(username)

        if user_data and hashlib.sha256(password.encode()).hexdigest() == user_data["password"]:
            keyboard_listener, mouse_listener = behavior_monitor.start_monitoring()
            print("Type your password again for behavioral verification...")
            input("Password: ")
            behavior_monitor.stop_monitoring(keyboard_listener, mouse_listener)

            if analyze_behavior(username, behavior_monitor.get_behavioral_data()):
                print("Behavioral verification successful!")
                if verify_2fa(username):
                    print("Login successful!")
                    return
                else:
                    print("2FA verification failed.")
            else:
                print("Behavioral verification failed.")
        else:
            print("Incorrect password.")

        attempts -= 1
        print(f"Attempts remaining: {attempts}")
    print("Login failed.")


if __name__ == "__main__":
    choice = input("Login (L) or Register (R)? ").upper()
    if choice == "R":
        register()
    else:
        login()
