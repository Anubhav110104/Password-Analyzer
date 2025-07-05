
# Password Analyzer – Web App

A smart web-based Password Strength Checker that analyzes your password, identifies weaknesses, checks for data breaches, and even suggests a strong alternative.

## Features
- Password Strength Scoring (out of 5)
- Entropy Calculation (in bits)
- Common Weakness Detection
- Breach Check using HaveIBeenPwned API
- Strong Password Generator
- Clean, Responsive UI with Bootstrap
- Also includes a Tkinter GUI version (pass.py)

## Technologies Used
- Python (Flask)
- HTML, CSS (Bootstrap)
- Requests, hashlib, math, re
- Tkinter (for desktop GUI)

## Usage
1. Clone the Repository
- git clone https://github.com/Anubhav110104/Brainwave_Matrix_Intern.git
- cd Password Strength Checker

2. Create and Activate Virtual Environment (Optional but recommended)
- python -m venv venv
  source venv/bin/activate  # For Windows: venv\Scripts\activate

3. Install Dependencies
- pip install flask requests

4. Run the App
- python app.py 

5. Open in Browser
- Navigate to http://127.0.0.1:5000 and start analyzing passwords!
