from flask import Flask, render_template, request
import string, re, math, hashlib, random, requests

app = Flask(__name__)

def load_common_passwords():
    return {"password", "123456", "qwerty", "letmein", "admin", "welcome", "password1", "123456789"}

def calculate_entropy(password):
    charset_size = 0
    if any(char.islower() for char in password): charset_size += 26
    if any(char.isupper() for char in password): charset_size += 26
    if any(char.isdigit() for char in password): charset_size += 10
    if any(char in string.punctuation for char in password): charset_size += len(string.punctuation)
    entropy = len(password) * math.log2(charset_size) if charset_size else 0
    return round(entropy, 2)

def check_password_leak(password):
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)
    return suffix in response.text

def analyze_password(password):
    score, weaknesses = 0, []
    if len(password) >= 12: score += 2
    elif len(password) >= 8: score += 1
    else: weaknesses.append("Use at least 12 characters.")
    
    if any(char.isdigit() for char in password): score += 1
    else: weaknesses.append("Add numbers.")
    
    if any(char.islower() for char in password) and any(char.isupper() for char in password): score += 1
    else: weaknesses.append("Use uppercase and lowercase letters.")
    
    if any(char in string.punctuation for char in password): score += 1
    else: weaknesses.append("Include special characters.")
    
    if password.lower() in load_common_passwords():
        weaknesses.append("Password is too common.")
    
    if re.search(r'(.)\1{2,}', password):
        weaknesses.append("Avoid repeated characters.")
    
    if check_password_leak(password):
        weaknesses.append("Password has been leaked in data breaches.")
    
    entropy = calculate_entropy(password)
    strength = "Weak" if score <= 2 else "Moderate" if score <= 4 else "Strong"
    return {
        "score": score,
        "strength": strength,
        "entropy": entropy,
        "weaknesses": weaknesses
    }

def generate_strong_password(length=16):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        if "analyze" in request.form:
            password = request.form.get("password")
            result = analyze_password(password)
        elif "generate" in request.form:
            result = {"generated": generate_strong_password()}
    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)

