import hashlib
import os
import pyotp
import base64
import qrcode
import cv2
import face_recognition
import numpy as np

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(stored_hash, entered_password):
    entered_hash = hash_password(entered_password)
    return stored_hash == entered_hash

def load_users(filename="users.txt"):
    users = {}
    if os.path.exists(filename):
        with open(filename, "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) == 2:
                    username, hashed_password = parts
                    users[username] = {"password": hashed_password, "secret": None, "face_encoding": None}
                elif len(parts) == 3:
                    username, hashed_password, secret = parts
                    users[username] = {"password": hashed_password, "secret": secret, "face_encoding": None}
                elif len(parts) == 4:
                    username, hashed_password, secret, face_encoding = parts
                    users[username] = {"password": hashed_password, "secret": secret, "face_encoding": face_encoding}
    return users

def save_users(users, filename="users.txt"):
    with open(filename, "w") as f:
        for username, user_data in users.items():
            face_encoding_str = user_data["face_encoding"] if user_data["face_encoding"] else ""
            if user_data["secret"]:
                f.write(f"{username}:{user_data['password']}:{user_data['secret']}:{face_encoding_str}\n")
            else:
                f.write(f"{username}:{user_data['password']}\n")

users = load_users()

def capture_face_encoding():
    for camera_index in range(10):  # Spróbuj indeksów kamer od 0 do 9
        try:
            kamera = cv2.VideoCapture(camera_index)
            if not kamera.isOpened():
                print(f"Odczytano obraz z kamery o indeksie {camera_index}.")
                continue  # Przejdź do następnego indeksu kamery
            ret, ramka = kamera.read()
            if not ret or ramka is None:
                print(f"Odczytano obraz z kamery o indeksie {camera_index}.")
                kamera.release()
                continue  # Przejdź do następnego indeksu kamery

            print(f"Używam kamery o indeksie {camera_index}.")
            kamera.release()
            ramka_rgb = cv2.cvtColor(ramka, cv2.COLOR_BGR2RGB)
            kodowanie_twarzy = face_recognition.face_encodings(ramka_rgb)
            if kodowanie_twarzy:
                return base64.b64encode(kodowanie_twarzy[0].tobytes()).decode('utf-8')
            else:
                print(f"Nie znaleziono twarzy w kadrze z kamery o indeksie {camera_index}.")
                return None

        except Exception as e:
            print(f"Błąd podczas przechwytywania twarzy z kamery o indeksie {camera_index}: {e}")
            return None
    print("Nie można znaleźć działającej kamery.")
    return None

def save_face_encoding(username, face_encoding):
    users[username]["face_encoding"] = face_encoding
    save_users(users)

def verify_face_encoding(username):
    try:
        stored_encoding = users[username].get("face_encoding")
        if not stored_encoding:
            return False
        stored_encoding_bytes = base64.b64decode(stored_encoding)
        stored_encoding_array = np.frombuffer(stored_encoding_bytes, dtype=np.float64)
        stored_encoding_array = [stored_encoding_array]

        capture_encoding = capture_face_encoding()
        if not capture_encoding:
            return False

        capture_encoding_bytes = base64.b64decode(capture_encoding)
        capture_encoding_array = np.frombuffer(capture_encoding_bytes, dtype=np.float64)
        capture_encoding_array = [capture_encoding_array]

        results = face_recognition.compare_faces(stored_encoding_array, capture_encoding_array[0])
        return results[0]
    except Exception as e:
        print(f"Błąd podczas weryfikacji twarzy: {e}")
        return False

def register():
    username = input("Username: ")
    password = input("Password: ")
    if username in users:
        print("Username already exists.")
        return
    hashed_password = hash_password(password)
    users[username] = {"password": hashed_password, "secret": None, "face_encoding": None}
    save_users(users)
    print("Registration successful!")
    enable_2fa(username)

    print("Capturing face encoding for facial verification...")
    face_encoding = capture_face_encoding()
    if face_encoding:
        save_face_encoding(username, face_encoding)
    else:
        print("Face capture failed. Facial verification will be skipped")

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
    secret = users[username]["secret"]
    if not secret:
        return True
    totp = pyotp.TOTP(secret)
    otp = input("Enter 2FA code: ")
    return totp.verify(otp)

def login():
    username = input("Username: ")
    password = input("Password: ")
    user_data = users.get(username)
    if user_data and verify_password(user_data["password"], password):
        if verify_2fa(username):
            print("Verifying face encoding for facial verification...")
            if verify_face_encoding(username):
                print("Login successful!")
            else:
                print("Facial verification failed.")
        else:
            print("2FA verification failed.")
    else:
        print("Login failed.")

choice = input("Login (L) or Register (R)? ").upper()
if choice == "R":
    register()
else:
    login()