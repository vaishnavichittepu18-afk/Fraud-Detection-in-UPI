from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from engine import FraudEngine
import sqlite3
import datetime
import re
import os

app = Flask(__name__)
app.secret_key = 'bank_security_secret_2024'

engine = FraudEngine()

# --- DATABASE HELPER ---
def get_db():
    conn = sqlite3.connect('system.db')
    conn.row_factory = sqlite3.Row
    return conn

def parse_amount(amount_input):
    """
    Parse amount from user input - handles:
    - Commas as thousand separators (1,000)
    - ₹ symbol (₹500)
    - Spaces (500 )
    - Decimal comma (1000,50)
    - Negative numbers (-500)
    - Zero (0)
    """
    if not amount_input:
        return 0
    
    amount_str = str(amount_input).strip()
    
    # Remove ₹ symbol
    amount_str = amount_str.replace('₹', '')
    
    # Handle comma as decimal separator (e.g., "1000,50" -> "1000.50")
    if ',' in amount_str and '.' not in amount_str:
        parts = amount_str.split(',')
        if len(parts) == 2 and len(parts[1]) <= 2:
            amount_str = amount_str.replace(',', '.')
    else:
        # Remove thousand separators
        amount_str = amount_str.replace(',', '')
    
    # Remove spaces
    amount_str = amount_str.replace(' ', '')
    
    # Remove any other non-numeric characters except decimal and minus
    amount_str = re.sub(r'[^\d.-]', '', amount_str)
    
    # Handle case where multiple decimals exist
    if amount_str.count('.') > 1:
        return None
    
    try:
        return float(amount_str)
    except ValueError:
        return None

def init_database():
    """Initialize database with correct schema"""
    conn = get_db()
    
    # Create users table
    conn.execute('''CREATE TABLE IF NOT EXISTS users 
        (username TEXT PRIMARY KEY, password TEXT)''')
    
    # Create merchants table
    conn.execute('''CREATE TABLE IF NOT EXISTS merchants 
        (vpa TEXT PRIMARY KEY, name TEXT, avg_amt REAL, trust_score INTEGER)''')
    
    # Create logs table with username column (not 'user')
    conn.execute('''CREATE TABLE IF NOT EXISTS logs 
        (id INTEGER PRIMARY KEY AUTOINCREMENT, 
         ts TEXT, 
         username TEXT, 
         vpa TEXT, 
         amt REAL, 
         score INTEGER, 
         status TEXT)''')
    
    # Create reports table for fraud reporting
    conn.execute('''CREATE TABLE IF NOT EXISTS reports 
        (id INTEGER PRIMARY KEY AUTOINCREMENT,
         vpa TEXT,
         reported_by TEXT,
         reason TEXT,
         ts TEXT)''')
    
    # Create blocked_vpas table
    conn.execute('''CREATE TABLE IF NOT EXISTS blocked_vpas 
        (vpa TEXT PRIMARY KEY, reason TEXT, blocked_at TEXT)''')
    
    # Add default users
    conn.execute("INSERT OR IGNORE INTO users VALUES ('admin', '123')")
    conn.execute("INSERT OR IGNORE INTO users VALUES ('test', 'test')")
    conn.execute("INSERT OR IGNORE INTO users VALUES ('student1', '123')")
    conn.execute("INSERT OR IGNORE INTO users VALUES ('student2', '123')")
    
    # Add default merchants
    merchants = [
        ('amazon@upi', 'Amazon Pay', 1200, 100),
        ('flipkart@oksbi', 'Flipkart', 2500, 100),
        ('zomato@paytm', 'Zomato', 400, 95),
        ('swiggy@upi', 'Swiggy', 350, 95),
        ('reliance.smart@icici', 'Reliance Retail', 3000, 100),
        ('googlepay@okaxis', 'Google Pay', 1500, 90),
        ('phonepe@ybl', 'PhonePe', 800, 90)
    ]
    conn.executemany("INSERT OR IGNORE INTO merchants VALUES (?,?,?,?)", merchants)
    
    conn.commit()
    conn.close()
    print("✅ Database initialized successfully!")

# Initialize database on startup
init_database()

# --- ROUTES ---

@app.route('/')
def home():
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        user = data.get('username', '').strip()
        pw = data.get('password', '').strip()

        db = get_db()
        account = db.execute("SELECT * FROM users WHERE username=? AND password=?", (user, pw)).fetchone()
        db.close()

        if account:
            session['logged_in'] = True
            session['user'] = user
            return jsonify({"status": "success"})
        return jsonify({"status": "error", "message": "Access Denied: Invalid Credentials"})
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({"status": "error", "message": str(e)})

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('home'))
    return render_template('index.html', user=session.get('user'))

@app.route('/scan', methods=['POST'])
def scan():
    if not session.get('logged_in'):
        return jsonify({"error": "Not logged in"}), 401
    
    try:
        data = request.json
        print(f"Received data: {data}")
        
        vpa = data.get('vpa', '').strip()
        
        # ========== FIX 1 & 2: Parse amount with commas, ₹ symbol, decimal comma ==========
        amt = parse_amount(data.get('amount', 0))
        
        # ========== FIX: Validate amount (negative and zero) ==========
        if amt is None:
            return jsonify({
                "score": 100,
                "status": "Fraudulent",
                "reasons": ["INVALID AMOUNT FORMAT: Please enter a valid number (e.g., 1000 or ₹1,000)"]
            })
        
        if amt < 0:
            return jsonify({
                "score": 100,
                "status": "Fraudulent",
                "reasons": ["INVALID TRANSACTION: Negative amount cannot be processed"]
            })
        
        if amt == 0:
            return jsonify({
                "score": 100,
                "status": "Fraudulent",
                "reasons": ["INVALID TRANSACTION: Zero amount transaction not allowed"]
            })
        
        qr = data.get('qr', '').strip()
        
        # Initialize variables
        total_score = 0
        all_reasons = []
        extracted_vpa = vpa
        
        # ========== FIX: Self-Payment Detection ==========
        current_user = session.get('user')
        
        # Extract VPA from QR if available
        if qr and qr.startswith("upi://pay"):
            pa_match = re.search(r'[?&]pa=([^&]+)', qr)
            if pa_match:
                extracted_vpa = pa_match.group(1)
        
        # Check if user is paying to themselves
        if extracted_vpa and current_user:
            vpa_username = extracted_vpa.split('@')[0].lower()
            current_user_lower = current_user.lower()
            
            # Check exact match
            if vpa_username == current_user_lower:
                return jsonify({
                    "score": 100,
                    "status": "Fraudulent",
                    "reasons": ["SELF-PAYMENT NOT ALLOWED: You cannot send money to yourself"]
                })
            
            # Also check if full VPA matches username@bank pattern
            self_patterns = [
                f"{current_user_lower}@upi",
                f"{current_user_lower}@paytm",
                f"{current_user_lower}@ybl",
                f"{current_user_lower}@sbi",
                f"{current_user_lower}@okaxis"
            ]
            if extracted_vpa.lower() in self_patterns:
                return jsonify({
                    "score": 100,
                    "status": "Fraudulent",
                    "reasons": ["SELF-PAYMENT NOT ALLOWED: You cannot send money to yourself"]
                })
        
        # 1. QR Analysis
        if qr:
            try:
                qr_score, qr_reasons, extracted_vpa, pn = engine.analyze_qr_deep(qr, amt)
                total_score += qr_score
                all_reasons.extend(qr_reasons)
                print(f"QR Analysis - Score: {qr_score}, Reasons: {qr_reasons}")
            except Exception as e:
                print(f"QR Analysis error: {e}")
                all_reasons.append(f"QR analysis error: {str(e)}")
        
        # 2. VPA Risk Check (includes missing '@' fix)
        if extracted_vpa:
            try:
                v_score, v_reasons = engine.check_vpa_risk(extracted_vpa, current_user)
                total_score += v_score
                all_reasons.extend(v_reasons)
                print(f"VPA Analysis - Score: {v_score}, Reasons: {v_reasons}")
            except Exception as e:
                print(f"VPA Analysis error: {e}")
                all_reasons.append(f"VPA analysis error: {str(e)}")
        
        # 3. Behavioral Check (includes >=5x fix)
        if extracted_vpa and amt > 0:
            try:
                b_score, b_reasons = engine.behavioral_check(extracted_vpa, amt, current_user)
                total_score += b_score
                all_reasons.extend(b_reasons)
                print(f"Behavioral Analysis - Score: {b_score}, Reasons: {b_reasons}")
            except Exception as e:
                print(f"Behavioral Analysis error: {e}")
                all_reasons.append(f"Behavioral analysis error: {str(e)}")
        
        # Cap score
        total_score = max(0, min(total_score, 100))
        
        # Remove duplicates
        all_reasons = list(dict.fromkeys(all_reasons))
        
        # Default message if no reasons
        if not all_reasons:
            all_reasons = ["No issues detected - Transaction appears normal"]
        
        # Determine status
        if total_score < 30:
            status = "Safe"
        elif total_score < 70:
            status = "Suspicious"
        else:
            status = "Fraudulent"
        
        # Save to database
        try:
            db = get_db()
            db.execute("""INSERT INTO logs (ts, username, vpa, amt, score, status) 
                          VALUES (?,?,?,?,?,?)""",
                       (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 
                        current_user, 
                        extracted_vpa or vpa, 
                        amt, 
                        total_score, 
                        status))
            db.commit()
            db.close()
            print(f"Transaction saved - Score: {total_score}, Status: {status}")
        except Exception as e:
            print(f"Database save error: {e}")
        
        return jsonify({
            "score": total_score, 
            "status": status, 
            "reasons": all_reasons
        })
        
    except Exception as e:
        print(f"Scan endpoint error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e), "score": 100, "status": "Error", "reasons": [f"System error: {str(e)}"]}), 500

@app.route('/history')
def history():
    if not session.get('logged_in'):
        return redirect(url_for('home'))
    
    try:
        db = get_db()
        logs = db.execute("SELECT * FROM logs WHERE username=? ORDER BY ts DESC", (session['user'],)).fetchall()
        db.close()
        return render_template('history.html', logs=logs, user=session['user'])
    except Exception as e:
        print(f"History error: {e}")
        return render_template('history.html', logs=[], user=session['user'])

@app.route('/report_vpa', methods=['POST'])
def report_vpa():
    if not session.get('logged_in'):
        return jsonify({"error": "Not logged in"}), 401
    
    try:
        data = request.json
        vpa = data.get('vpa')
        reason = data.get('reason', 'Suspicious activity')
        
        db = get_db()
        
        # Check existing reports
        report_count = db.execute("SELECT COUNT(*) as count FROM reports WHERE vpa=?", (vpa,)).fetchone()['count']
        
        # Add report
        db.execute("INSERT INTO reports (vpa, reported_by, reason, ts) VALUES (?,?,?,?)",
                   (vpa, session['user'], reason, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        
        # Block if 3+ reports
        if report_count + 1 >= 3:
            db.execute("INSERT OR IGNORE INTO blocked_vpas VALUES (?,?,?)",
                       (vpa, "Blocked due to multiple user reports", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            db.commit()
            db.close()
            return jsonify({"status": "blocked", "message": "VPA has been blocked", "reports": report_count + 1})
        
        db.commit()
        db.close()
        return jsonify({"status": "reported", "reports": report_count + 1})
        
    except Exception as e:
        print(f"Report error: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, host='127.0.0.1', port=5000)