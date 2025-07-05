
# it is using tkinter for web-app 

import re
import string
import os
import random
import math
import requests
import hashlib
from tkinter import Tk, Label, Entry, Button, Text, END, Frame, Scrollbar

# Load common weak passwords
def load_common_passwords():
    weak_passwords = {"password", "123456", "qwerty", "letmein", "admin", "welcome", "password1", "123456789"}
    return weak_passwords

# Function to calculate password entropy
def calculate_entropy(password):
    charset_size = 0
    if any(char.islower() for char in password):
        charset_size += 26
    if any(char.isupper() for char in password):
        charset_size += 26
    if any(char.isdigit() for char in password):
        charset_size += 10
    if any(char in string.punctuation for char in password):
        charset_size += len(string.punctuation)
    
    entropy = len(password) * math.log2(charset_size) if charset_size else 0
    return round(entropy, 2)

# Function to check if the password has been leaked in breaches
def check_password_leak(password):
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)
    if suffix in response.text:
        return True
    return False

# Function to analyze password strength
def analyze_password(password):
    score = 0
    weaknesses = []
    
    # Check length
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        weaknesses.append("Password is too short. Use at least 12 characters.")
    
    # Check character variety
    if any(char.isdigit() for char in password):
        score += 1
    else:
        weaknesses.append("Add numbers to strengthen the password.")
    
    if any(char.islower() for char in password) and any(char.isupper() for char in password):
        score += 1
    else:
        weaknesses.append("Use a mix of uppercase and lowercase letters.")
    
    if any(char in string.punctuation for char in password):
        score += 1
    else:
        weaknesses.append("Include special characters (e.g., !@#$%^&*).")
    
    # Check for common passwords
    common_passwords = load_common_passwords()
    if password.lower() in common_passwords:
        weaknesses.append("Your password is too common. Choose a unique one.")
    
    # Check for repeated characters or patterns
    if re.search(r'(.)\1{2,}', password):
        weaknesses.append("Avoid repeating characters too many times.")
    
    # Check if the password has been leaked
    if check_password_leak(password):
        weaknesses.append("Your password has been leaked in data breaches! Choose a new one.")
    
    # Calculate entropy
    entropy = calculate_entropy(password)
    
    # Provide feedback
    strength = "Weak" if score <= 2 else "Moderate" if score <= 4 else "Strong"
    return {
        "score": score,
        "strength": strength,
        "entropy": entropy,
        "weaknesses": weaknesses
    }

# Function to generate a strong password
def generate_strong_password(length=16):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

# GUI Application using Tkinter
def analyze_from_gui():
    password = password_entry.get()
    result = analyze_password(password)
    result_text.delete(1.0, END)
    result_text.insert(END, f"Strength: {result['strength']} (Score: {result['score']}/5)\n")
    result_text.insert(END, f"Entropy: {result['entropy']} bits\n\n")
    if result['weaknesses']:
        result_text.insert(END, "Weaknesses:\n")
        for weakness in result['weaknesses']:
            result_text.insert(END, f"- {weakness}\n")
    else:
        result_text.insert(END, "Your password is strong!\n")

def generate_password_from_gui():
    new_password = generate_strong_password()
    result_text.delete(1.0, END)
    result_text.insert(END, f"Generated Secure Password: {new_password}\n")

# Tkinter GUI setup
root = Tk()
root.title("Password Analyzer")
root.geometry("500x400")
root.configure(bg="#2C3E50")

frame = Frame(root, bg="#34495E", padx=10, pady=10)
frame.pack(pady=20)

Label(frame, text="Enter Password:", font=("Arial", 12), bg="#34495E", fg="white").pack()
password_entry = Entry(frame, show="*", width=30, font=("Arial", 12))
password_entry.pack(pady=5)

Button(frame, text="Analyze Password", command=analyze_from_gui, font=("Arial", 12), bg="#1ABC9C", fg="white").pack(pady=5)
Button(frame, text="Generate Strong Password", command=generate_password_from_gui, font=("Arial", 12), bg="#E74C3C", fg="white").pack(pady=5)

result_text = Text(root, height=10, width=60, font=("Arial", 10), bg="#ECF0F1", wrap="word")
scrollbar = Scrollbar(root, command=result_text.yview)
result_text.configure(yscrollcommand=scrollbar.set)
result_text.pack(pady=10)
scrollbar.pack(side="right", fill="y")

root.mainloop()
