from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from functools import wraps
import os
import shutil


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///madlab.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Create database
with app.app_context():
    db.create_all()

app.secret_key = 'your_secret_key'  # Change this to a secure secret key

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('You need to login first!', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    faqs = [
        {
            "question": "What is MadLab?",
            "answer": "MadLab is a revolutionary scientific writing service that bridges the gap between laboratory work and publication. We utilize advanced AI technology to transform your experimental results into comprehensive research papers through an iterative peer review system."
        },
        {
            "question": "How long does the process take?",
            "answer": "Our AI-powered system typically delivers completed research papers within 4-24 hours, depending on the complexity and nature of the research."
        },
        {
            "question": "What fields of science does MadLab cover?",
            "answer": "We currently support research in Life Sciences, Chemistry, Physics, Engineering, Environmental Science, Materials Science, Medical Research, and Computer Science."
        },
        {
            "question": "How does pricing work?",
            "answer": "We maintain transparent pricing at 250 USD per research paper, including the complete paper writing process and two rounds of revisions."
        },
        {
            "question": "How do I get started with MadLab?",
            "answer": "Getting started is easy: Contact our team to discuss your research paper, submit your research results and requirements, receive your first draft within 1-2 hours, and request up to two rounds of revisions if needed."
        }
    ]
    return render_template('home.html', faqs=faqs)
    
@app.route('/submit', methods=['GET', 'POST'])
@login_required
def submit_research():
    if request.method == 'POST':
        form_data = {
            'title': request.form.get('title'),
            'objective': request.form.get('objective'),
            'keywords': request.form.get('keywords'),
            'hypothesis': request.form.get('hypothesis'),
            'bibtex': request.form.get('bibtex'),
            'datasetSource': request.form.get('datasetSource'),
            'datasetSize': request.form.get('datasetSize'),
            'keyVariables': request.form.get('keyVariables'),
            'preprocessing': request.form.get('preprocessing'),
            'algorithm': request.form.get('algorithm'),
            'parameters': request.form.get('parameters'),
            'results': request.form.get('results'),
            'limitations': request.form.get('limitations')
        }
        # Create a new folder with timestamp to ensure unique names
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        folder_name = f"research_{session['user'].split('@')[0]}_{timestamp}"
        folder_path = os.path.join("AI-Scientist/results", folder_name)
        
        try:
            # Create the new folder
            os.makedirs(folder_path)

            # Copy latex folder from root to new folder
            latex_source = os.path.join(os.getcwd(), 'latex')
            latex_destination = os.path.join(folder_path, 'latex')
            if os.path.exists(latex_source):
                shutil.copytree(latex_source, latex_destination)

            # Create and write to notes.txt
            notes_path = os.path.join(folder_path, 'notes.txt')
            with open(notes_path, 'w') as f:
                f.write("Research Project Details\n")
                f.write("======================\n\n")
                
                # Write each form field with proper formatting
                for key, value in form_data.items():
                    if key!="bibtex":
                        # Capitalize and format the key
                        formatted_key = key.replace('dataset', 'Dataset ').title()
                        f.write(f"{formatted_key}:\n")
                        f.write("-" * (len(formatted_key) + 1) + "\n")
                        f.write(f"{value if value else 'Not provided'}\n\n")
                        
            # bibtex_dist = os.path.join(latex_destination, 'latex')
            notes_path = os.path.join(latex_destination, 'references.bib')
            with open(notes_path, 'w') as f:
                bib_data = form_data["bibtex"]
                f.write(bib_data)

            return redirect(url_for('home'))

        except Exception as e:
            # Handle any errors that might occur during folder creation or file operations
            print(f"Error: {str(e)}")
            return "An error occurred while processing your submission", 500
        # Add your form processing logic here
        return redirect(url_for('home'))
    return render_template('submit.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists!', 'error')
            return redirect(url_for('signup'))
            
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('signup'))
            
        hashed_password = generate_password_hash(password)
        new_user = User(email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))
        
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user'] = email
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password!', 'error')
            return redirect(url_for('login'))
        
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)