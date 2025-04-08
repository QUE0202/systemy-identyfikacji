import hashlib
import os
import pyotp
import base64
import qrcode
import time
from pynput import keyboard, mouse
from sklearn.svm import SVC
import numpy as np

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

class BehaviorModel:
    def __init__(self):
        self.model = SVC(kernel='linear')  # Prosty model SVM
        self.data = []
        self.labels = []

    def train(self, behavior_data, label):
        key_timings = behavior_data["key_timings"]
        mouse_movements = behavior_data["mouse_movements"]
        features = np.array(key_timings + mouse_movements).reshape(1, -1)
        self.data.append(features)
        self.labels.append(label)
        self.model.fit(self.data, self.labels)

    def predict(self, behavior_data):
        key_timings = behavior_data["key_timings"]
        mouse_movements = behavior_data["mouse_movements"]
        features = np.array(key_timings + mouse_movements).reshape(1, -1)
        return self.model.predict(features)[0]

behavior_monitor = BehaviorMonitor()
users = {}
behavior_model = BehaviorModel()

def save_users(users, filename="users.txt"):
    with open(filename, "w") as f:
        for username, user_data in users.items():
            behavior_data = base64.b64encode(str(user_data["behavior"]).encode()).decode() if user_data["behavior"] else ""
            f.write(f"{username}:{user_data['password']}:{user_data['secret']}:{behavior_data}\n")

def load_users(filename="users.txt"):
    global users
    if os.path.exists(filename):
        with open(filename, "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 3:
                    username, hashed_password, secret = parts[:3]
                    behavior = base64.b64decode(parts[3]).decode() if len(parts) == 4 and parts[3] else None
                    users[username] = {"password": hashed_password, "secret": secret, "behavior": eval(behavior) if behavior else None}
                    if users[username]["behavior"]:
                        behavior_model.train(users[username]["behavior"], username)

load_users()

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

def register():
    username = input("Username: ")
    password = input("Password: ")

    if username in users:
        print("Username already exists.")
        return

    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    users[username] = {"password": hashed_password, "secret": None, "behavior": None}

    keyboard_listener, mouse_listener = behavior_monitor.start_monitoring()
    print("Type your password again to record behavioral data...")
    input("Password: ")
    behavior_monitor.stop_monitoring(keyboard_listener, mouse_listener)

    users[username]["behavior"] = behavior_monitor.get_behavioral_data()
    behavior_model.train(users[username]["behavior"], username)
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

            if behavior_model.predict(behavior_monitor.get_behavioral_data()) == username:
                print("Login successful!")
                return
            else:
                print("Behavioral verification failed.")
        else:
            print("Incorrect password.")

        attempts -= 1
        print(f"Attempts remaining: {attempts}")
    print("Login failed.")

choice = input("Login (L) or Register (R)? ").upper()
if choice == "R":
    register()
else:
    login()
