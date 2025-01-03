from flask import Flask, render_template_string, render_template, request, jsonify, url_for, flash, session, redirect
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import subprocess
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from models import db,User

app = Flask(__name__,template_folder='../frontend',static_folder='../frontend/static')
app.config['SECRET_KEY'] = '9b3c7cabc49e4f8e8c676b04fa35f37a47c95195e1674e36e1a9d47bcd1935fd'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

login_manager = LoginManager(app)
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

CORS(app)

users = {}

model_name = "distilgpt2"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForCausalLM.from_pretrained(model_name).to('cpu') 

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Check if password length is at least 6 characters
        if len(password) < 6:
            return render_template('register.html', error="Password must be at least 6 characters!")
        
        # Check if password and confirm password match
        if password != confirm_password:
            return render_template('register.html', error="Passwords do not match.")
        
        # Proceed with registration logic here (e.g., saving to the database)
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!','success')
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')

    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('index.html') 

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    username = current_user.email.split('@')[0]
    return render_template('index.html', username=username)

@app.route('/landing')
def landing():
    return render_template('landing.html')

@app.route('/execute', methods=['POST'])
def execute_code():
    data = request.json
    if not data or 'code' not in data:
        return jsonify({'error': 'Invalid code'}),400

    code = data['code']
    file_path = os.path.join(os.getcwd(), 'temp_code.py')

    try:
        with open(file_path, 'w') as f:
            f.write(code)

        result = subprocess.run(['python', file_path], capture_output=True, text=True)
        os.remove(file_path)

        if result.returncode == 0:
            return jsonify({'output': result.stdout}), 200
        else:
            return jsonify({'error': result.stderr}), 400

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/chat', methods=['POST'])
def chat():
    data = request.json
    user_message = data.get("message")
    editor_code = data.get("code")
    
    try:
        user_message = request.json.get("message")
        
        if not user_message or not editor_code:
            print("No message received") 
            return jsonify({"error": "Message is required"}), 400

        prompt = f"Here is the python code:\n\n{editor_code}\n\n{user_message}\n\nAI response:"

        print(f"Received user message: {prompt}")
        
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token
        inputs = tokenizer.encode(prompt, return_tensors='pt',padding=True,truncation=True).to("cpu")
        attention_mask = inputs != tokenizer.pad_token_id
        outputs = model.generate(
                inputs, 
                max_length=150,
                temperature=0.7,
                do_sample=True,
                attention_mask=attention_mask,
                pad_token_id=tokenizer.pad_token_id
                )
        response = tokenizer.decode(outputs[0], skip_special_tokens=True).split("AI response:")[-1].strip()
            
        print(f"Generated AI Response: {response}") 
        return jsonify({"response": response})
    
    except Exception as e:
        print(f"Unexpected error: {e}")
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True)
