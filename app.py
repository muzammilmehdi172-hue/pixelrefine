from flask import Flask, render_template, request, send_from_directory, jsonify, session, redirect, url_for
import os
import cv2
import numpy as np
from werkzeug.utils import secure_filename
import urllib.request
import urllib.error
import sqlite3
from contextlib import closing
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image
import secrets
from datetime import datetime, timedelta
import json

# === INIT ===
app = Flask(__name__)
app.secret_key = 'pixelrefine-secret-key-2025'  # Change this in production!

# === FOLDERS ===
os.makedirs('uploads', exist_ok=True)
os.makedirs('results', exist_ok=True)
os.makedirs('models', exist_ok=True)
os.makedirs('templates', exist_ok=True)
os.makedirs('static', exist_ok=True)

# === DATABASE FUNCTIONS ===
def get_db():
    conn = sqlite3.connect('users.db', check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with closing(get_db()) as db:
        # Users table
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                free_enhancements_used INTEGER DEFAULT 0,
                is_premium BOOLEAN DEFAULT FALSE,
                total_donations REAL DEFAULT 0
            )
        ''')
        
        # Password reset tokens table
        db.execute('''
            CREATE TABLE IF NOT EXISTS password_resets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                reset_token TEXT UNIQUE NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                used BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Donations table
        db.execute('''
            CREATE TABLE IF NOT EXISTS donations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                amount REAL NOT NULL,
                tier TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # User sessions table
        db.execute('''
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                session_token TEXT UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # User images table
        db.execute('''
            CREATE TABLE IF NOT EXISTS user_images (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                original_filename TEXT,
                enhanced_filename TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        db.commit()
    print("✅ Database initialized successfully!")

def create_session_token(user_id):
    session_token = secrets.token_urlsafe(32)
    expires_at = datetime.now() + timedelta(days=30)  # 30-day sessions
    
    with closing(get_db()) as db:
        db.execute(
            'INSERT INTO user_sessions (user_id, session_token, expires_at) VALUES (?, ?, ?)',
            (user_id, session_token, expires_at)
        )
        db.commit()
    
    return session_token

def validate_session_token(session_token):
    with closing(get_db()) as db:
        session_data = db.execute(
            'SELECT user_id FROM user_sessions WHERE session_token = ? AND expires_at > ?',
            (session_token, datetime.now())
        ).fetchone()
        
        return session_data['user_id'] if session_data else None

def get_current_user():
    session_token = session.get('session_token')
    if session_token:
        user_id = validate_session_token(session_token)
        if user_id:
            with closing(get_db()) as db:
                user = db.execute(
                    'SELECT id, email, free_enhancements_used, is_premium, total_donations FROM users WHERE id = ?',
                    (user_id,)
                ).fetchone()
                return dict(user) if user else None
    return None

# === PASSWORD RESET FUNCTIONS ===
def send_reset_email(user_email, reset_token):
    """Send password reset email (simplified version - in production, use a proper email service)"""
    try:
        reset_link = f"http://localhost:5000/reset-password?token={reset_token}"
        
        # For development, we'll just log the reset link
        print(f"📧 Password reset link for {user_email}: {reset_link}")
        print(f"🔗 Reset URL: {reset_link}")
        
        # In production, you would send an actual email here
        # Using services like SendGrid, Mailgun, or SMTP
        
        return True
    except Exception as e:
        print(f"Email sending failed: {e}")
        return False

# === AUTH ROUTES ===
@app.route('/signin')
def signin_page():
    return render_template('signin.html')

@app.route('/signup')
def signup_page():
    return render_template('signup.html')

@app.route('/forgot-password')
def forgot_password_page():
    return render_template('forgot-password.html')

@app.route('/reset-password')
def reset_password_page():
    token = request.args.get('token')
    return render_template('reset-password.html', token=token)

@app.route('/api/login', methods=['POST'])
def login_api():
    email = request.form.get('email', '').lower().strip()
    password = request.form.get('password', '')
    
    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400
    
    with closing(get_db()) as db:
        user = db.execute(
            'SELECT id, email, password_hash FROM users WHERE email = ?',
            (email,)
        ).fetchone()
        
        if user and check_password_hash(user['password_hash'], password):
            session_token = create_session_token(user['id'])
            session['session_token'] = session_token
            session['user_id'] = user['id']
            
            return jsonify({
                "success": True,
                "message": "Login successful!",
                "user": {
                    "id": user['id'],
                    "email": user['email']
                }
            })
        
        return jsonify({"error": "Invalid email or password"}), 401

@app.route('/api/signup', methods=['POST'])
def signup_api():
    email = request.form.get('email', '').lower().strip()
    password = request.form.get('password', '')
    
    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400
    
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    
    try:
        with closing(get_db()) as db:
            db.execute(
                'INSERT INTO users (email, password_hash) VALUES (?, ?)',
                (email, generate_password_hash(password))
            )
            db.commit()
            
            # Log the user in automatically after signup
            user = db.execute(
                'SELECT id, email FROM users WHERE email = ?',
                (email,)
            ).fetchone()
            
            session_token = create_session_token(user['id'])
            session['session_token'] = session_token
            session['user_id'] = user['id']
            
            return jsonify({
                "success": True,
                "message": "Account created successfully!",
                "user": {
                    "id": user['id'],
                    "email": user['email']
                }
            })
            
    except sqlite3.IntegrityError:
        return jsonify({"error": "An account with this email already exists"}), 400
    except Exception as e:
        return jsonify({"error": "An error occurred during signup"}), 500

@app.route('/api/forgot-password', methods=['POST'])
def forgot_password_api():
    email = request.json.get('email', '').lower().strip()
    
    if not email:
        return jsonify({"error": "Email is required"}), 400
    
    try:
        with closing(get_db()) as db:
            user = db.execute(
                'SELECT id FROM users WHERE email = ?',
                (email,)
            ).fetchone()
            
            if user:
                # Generate reset token
                reset_token = secrets.token_urlsafe(32)
                expires_at = datetime.now() + timedelta(hours=1)
                
                # Store reset token
                db.execute(
                    'INSERT INTO password_resets (user_id, reset_token, expires_at) VALUES (?, ?, ?)',
                    (user['id'], reset_token, expires_at)
                )
                db.commit()
                
                # Send reset email
                if send_reset_email(email, reset_token):
                    return jsonify({
                        "success": True,
                        "message": "Password reset instructions have been sent to your email."
                    })
                else:
                    return jsonify({
                        "error": "Failed to send email. Please try again later."
                    }), 500
            else:
                # Don't reveal whether email exists for security
                return jsonify({
                    "success": True,
                    "message": "If that email exists in our system, reset instructions have been sent."
                })
                
    except Exception as e:
        print(f"Password reset error: {e}")
        return jsonify({"error": "An error occurred. Please try again."}), 500

@app.route('/api/reset-password', methods=['POST'])
def reset_password_api():
    token = request.json.get('token')
    new_password = request.json.get('password')
    
    if not token or not new_password:
        return jsonify({"error": "Token and password are required"}), 400
    
    if len(new_password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    
    try:
        with closing(get_db()) as db:
            # Find valid reset token
            reset_request = db.execute(
                '''SELECT user_id FROM password_resets 
                   WHERE reset_token = ? AND expires_at > ? AND used = FALSE''',
                (token, datetime.now())
            ).fetchone()
            
            if reset_request:
                user_id = reset_request['user_id']
                
                # Update password
                db.execute(
                    'UPDATE users SET password_hash = ? WHERE id = ?',
                    (generate_password_hash(new_password), user_id)
                )
                
                # Mark token as used
                db.execute(
                    'UPDATE password_resets SET used = TRUE WHERE reset_token = ?',
                    (token,)
                )
                
                db.commit()
                
                return jsonify({
                    "success": True,
                    "message": "Password has been reset successfully. You can now log in with your new password."
                })
            else:
                return jsonify({"error": "Invalid or expired reset token"}), 400
                
    except Exception as e:
        print(f"Password reset error: {e}")
        return jsonify({"error": "An error occurred. Please try again."}), 500

@app.route('/api/logout', methods=['POST'])
def logout_api():
    session_token = session.get('session_token')
    if session_token:
        with closing(get_db()) as db:
            db.execute('DELETE FROM user_sessions WHERE session_token = ?', (session_token,))
            db.commit()
    
    session.clear()
    return jsonify({"success": True, "message": "Logged out successfully"})

@app.route('/api/user')
def user_api():
    user = get_current_user()
    if user:
        return jsonify({
            "is_authenticated": True,
            "user": {
                "id": user['id'],
                "email": user['email'],
                "free_enhancements_used": user['free_enhancements_used'],
                "is_premium": bool(user['is_premium']),
                "total_donations": user['total_donations'] or 0
            }
        })
    else:
        return jsonify({"is_authenticated": False})

# === DONATION ROUTES ===
@app.route('/api/donate', methods=['POST'])
def donate_api():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Please log in to donate"}), 401
    
    data = request.get_json()
    amount = data.get('amount', 0)
    tier = data.get('tier', 'custom')
    
    if amount <= 0:
        return jsonify({"error": "Invalid donation amount"}), 400
    
    try:
        with closing(get_db()) as db:
            # Record donation
            db.execute(
                'INSERT INTO donations (user_id, amount, tier) VALUES (?, ?, ?)',
                (user['id'], amount, tier)
            )
            
            # Update user's total donations
            db.execute(
                'UPDATE users SET total_donations = total_donations + ? WHERE id = ?',
                (amount, user['id'])
            )
            
            # If donation is $15 or more, grant premium status
            if amount >= 15:
                db.execute(
                    'UPDATE users SET is_premium = TRUE WHERE id = ?',
                    (user['id'],)
                )
            
            db.commit()
            
            return jsonify({
                "success": True,
                "message": f"Thank you for your ${amount} donation!",
                "is_premium": amount >= 15
            })
            
    except Exception as e:
        return jsonify({"error": "Donation failed"}), 500

# === MODEL DOWNLOAD ===
GFPGAN_URL = "https://github.com/TencentARC/GFPGAN/releases/download/v1.3.0/GFPGANv1.4.pth"
ESRGAN_URL = "https://github.com/xinntao/Real-ESRGAN/releases/download/v0.2.1/RealESRGAN_x2plus.pth"
GFPGAN_PATH = "models/GFPGANv1.4.pth"
ESRGAN_PATH = "models/RealESRGAN_x2plus.pth"

def download_if_missing(url, path):
    if not os.path.exists(path):
        print(f"📥 Downloading {os.path.basename(path)}...")
        try:
            urllib.request.urlretrieve(url, path)
            print("✅ Download complete.")
        except Exception as e:
            print(f"❌ Download failed: {e}")

# Download models if missing
try:
    download_if_missing(GFPGAN_URL, GFPGAN_PATH)
    download_if_missing(ESRGAN_URL, ESRGAN_PATH)
except Exception as e:
    print(f"⚠️ Model download failed: {e}")

# === LOAD MODELS ===
gfpgan_restorer = None
realesrgan_enhancer = None

try:
    from gfpgan import GFPGANer
    from realesrgan import RealESRGANer
    from basicsr.archs.rrdbnet_arch import RRDBNet

    gfpgan_restorer = GFPGANer(model_path=GFPGAN_PATH, upscale=2, bg_upsampler=None)
    realesrgan_enhancer = RealESRGANer(
        scale=2,
        model_path=ESRGAN_PATH,
        model=RRDBNet(num_in_ch=3, num_out_ch=3, num_feat=64, num_block=23, num_grow_ch=32, scale=2),
        tile=256,
        half=False
    )
    print("✅ AI Models loaded successfully!")
except Exception as e:
    print(f"⚠️ Failed to load AI models: {e}")

# === AI ENHANCEMENT ===
def can_user_enhance(user):
    """Check if user can perform enhancement"""
    if not user:
        return False, "Please log in to enhance images"
    
    if user.get('is_premium'):
        return True, "Premium user"
    
    free_enhancements_used = user.get('free_enhancements_used', 0)
    if free_enhancements_used < 10:
        return True, f"Free enhancements remaining: {10 - free_enhancements_used}"
    else:
        return False, "Free tier limit reached. Please donate to get premium access."

@app.route('/upload', methods=['POST'])
def upload():
    user = get_current_user()
    can_enhance, message = can_user_enhance(user)
    
    if not can_enhance:
        return jsonify({"success": False, "error": message}), 403
    
    if 'file' not in request.files:
        return jsonify({"success": False, "error": "No file uploaded"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"success": False, "error": "No file selected"}), 400
    
    filename = secure_filename(file.filename)
    input_path = f"uploads/{filename}"
    output_path = f"results/enhanced_{filename}"
    
    try:
        # Resize large images to prevent OOM
        img_pil = Image.open(file.stream)
        if max(img_pil.size) > 1200:
            img_pil.thumbnail((1200, 1200), Image.LANCZOS)
        img_pil.save(input_path)
        
        # Process with AI if models are available
        if gfpgan_restorer and realesrgan_enhancer:
            img = cv2.imread(input_path)
            _, _, restored = gfpgan_restorer.enhance(img, has_aligned=False, only_center_face=False, paste_back=True)
            upscaled, _ = realesrgan_enhancer.enhance(restored)
            cv2.imwrite(output_path, upscaled)
        else:
            # Fallback: just copy the image if AI models aren't loaded
            img_pil.save(output_path)
        
        # Update user's enhancement count
        if user and not user.get('is_premium'):
            with closing(get_db()) as db:
                db.execute(
                    'UPDATE users SET free_enhancements_used = free_enhancements_used + 1 WHERE id = ?',
                    (user['id'],)
                )
                db.commit()
        
        # Record image in database
        if user:
            with closing(get_db()) as db:
                db.execute(
                    'INSERT INTO user_images (user_id, original_filename, enhanced_filename) VALUES (?, ?, ?)',
                    (user['id'], filename, f"enhanced_{filename}")
                )
                db.commit()
        
        return jsonify({
            "success": True,
            "before_url": f"/uploads/{filename}",
            "after_url": f"/results/enhanced_{filename}",
            "message": "Image enhanced successfully!"
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": f"Enhancement failed: {str(e)}"}), 500

# === STATIC FILES ===
@app.route('/uploads/<path>')
def uploads(path):
    return send_from_directory('uploads', path)

@app.route('/results/<path>')
def results(path):
    return send_from_directory('results', path)

# === PAGES ROUTES ===
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('index.html')

@app.route('/features')
def features():
    return render_template('index.html')

@app.route('/donation')
def donation():
    return render_template('index.html')

@app.route('/contact')
def contact():
    return render_template('index.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

# === INITIALIZE DATABASE ===
init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"🚀 Starting PixelRefine AI on port {port}...")
    app.run(host="0.0.0.0", port=port, debug=False)