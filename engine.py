import re
import sqlite3
from datetime import datetime, timedelta
from difflib import SequenceMatcher

class FraudEngine:
    def __init__(self):
        self.user_history = {}      # Tracks ALL transactions per user
        self.vpa_history = {}       # Tracks per-VPA transactions per user
        
        self.official_brands = ['amazon', 'flipkart', 'zomato', 'swiggy', 'paytm', 
                                'phonepe', 'googlepay', 'sbi', 'hdfc', 'icici']
        
        self.suspicious_keywords = ['verify', 'reward', 'cashback', 'secure', 'support', 
                                    'help', 'customer', 'care', 'refund', 'prize', 
                                    'winner', 'lottery', 'gift', 'voucher']

    def get_db_connection(self):
        return sqlite3.connect('system.db')

    def normalize_vpa(self, text):
        if not text:
            return ""
        text = str(text).lower().strip()
        text = re.sub(r'[^\w@.-]', '', text)
        return text

    def extract_vpa_from_qr(self, payload):
        if not payload:
            return None
        match = re.search(r'pa=([^&]+)', payload)
        if match:
            return self.normalize_vpa(match.group(1))
        return None

    def check_self_payment(self, vpa, username):
        """Check if user is trying to pay themselves"""
        if not vpa or not username:
            return False
        
        norm_vpa = self.normalize_vpa(vpa)
        norm_username = username.lower()
        
        # Extract username part from VPA
        vpa_username = norm_vpa.split('@')[0]
        
        # Check if VPA username matches logged-in user
        if vpa_username == norm_username:
            return True
        
        # Check common self-payment patterns
        self_patterns = [
            f"{norm_username}@upi",
            f"{norm_username}@paytm", 
            f"{norm_username}@ybl",
            f"{norm_username}@sbi",
            f"{norm_username}@okaxis"
        ]
        
        if norm_vpa in self_patterns:
            return True
        
        return False

    def check_vpa_risk(self, vpa, username=None):
        norm_vpa = self.normalize_vpa(vpa)
        if not norm_vpa:
            return 0, ["No VPA provided"]
        
        score = 0
        reasons = []
        
        # ========== FIX: Missing '@' - Block immediately ==========
        if '@' not in norm_vpa:
            return 100, ["REJECTED: Invalid UPI VPA format - Missing '@' symbol (e.g., username@bank)"]
        
        # ========== Self-Payment Check ==========
        if username and self.check_self_payment(norm_vpa, username):
            return 100, ["SELF-PAYMENT NOT ALLOWED: You cannot send money to yourself"]
        
        if len(norm_vpa.split('@')[0]) < 2:
            score += 30
            reasons.append("Suspicious VPA - Username too short")
        
        conn = self.get_db_connection()
        
        # Check verified merchant
        merchant = conn.execute("SELECT name, trust_score FROM merchants WHERE vpa=?", (norm_vpa,)).fetchone()
        
        # Check past transactions
        past_tx = conn.execute("SELECT COUNT(*), AVG(score) FROM logs WHERE vpa=?", (norm_vpa,)).fetchone()
        
        # Check reports
        report_count = conn.execute("SELECT COUNT(*) as count FROM reports WHERE vpa=?", (norm_vpa,)).fetchone()
        report_count = report_count[0] if report_count else 0
        
        # Check blocked
        blocked = conn.execute("SELECT * FROM blocked_vpas WHERE vpa=?", (norm_vpa,)).fetchone()
        
        conn.close()
        
        # Blocked VPA
        if blocked:
            return 100, ["🚨 This VPA has been BLOCKED due to multiple fraud reports!"]
        
        # Verified merchant
        if merchant:
            return -50, [f"✓ Verified Merchant: {merchant['name']} (Trust Score: {merchant['trust_score']}/100)"]
        
        # Trusted contact
        if past_tx and past_tx[0] >= 2:
            avg_score = past_tx[1] if past_tx[1] else 0
            if avg_score < 30:
                return -30, [f"✓ Known Contact: Recognized from {past_tx[0]} previous safe transactions"]
        
        # Reported VPA
        if report_count >= 2:
            score += 40
            reasons.append(f"⚠️ This VPA has been reported {report_count} times for suspicious activity")
        
        # Unverified account
        score += 35
        reasons.append("⚠️ Unverified Account: This VPA is not in the verified business registry")
        
        # Suspicious keywords
        vpa_prefix = norm_vpa.split('@')[0]
        for keyword in self.suspicious_keywords:
            if keyword in vpa_prefix:
                score += 25
                reasons.append(f"🚨 Suspicious Keyword: '{keyword}' found in VPA - Common fraud pattern")
                break
        
        # Brand spoofing
        for brand in self.official_brands:
            similarity = SequenceMatcher(None, vpa_prefix, brand).ratio()
            if brand in vpa_prefix or similarity > 0.75:
                if vpa_prefix != brand:
                    score += 55
                    reasons.append(f"🚨 BRAND SPOOFING: Account mimics '{brand.upper()}' but is NOT the official VPA!")
                    break
        
        # Typosquatting
        if re.search(r'\d+', vpa_prefix) and len(vpa_prefix) > 5:
            score += 15
            reasons.append("⚠️ Suspicious Pattern: Numbers in merchant name - Possible typosquatting")
        
        # Personal account
        personal_suffixes = ['@sbi', '@ybl', '@okaxis', '@oksbi', '@paytm', '@icici', '@hdfc']
        if any(norm_vpa.endswith(suffix) for suffix in personal_suffixes):
            score += 10
            reasons.append("⚠️ Personal Account: Higher risk for merchant transactions")
        
        return min(score, 100), reasons

    def analyze_qr_deep(self, payload, user_amt):
        if not payload:
            return 0, [], None, ""

        if not payload.startswith("upi://pay"):
            return 100, ["🚨 CRITICAL: This is NOT a UPI payment QR! Possible phishing attempt."], None, "Non-UPI"

        params = {}
        param_matches = re.findall(r'([a-zA-Z0-9_]+)=([^&]*)', payload)
        for key, value in param_matches:
            value = value.replace('%20', ' ').replace('%40', '@')
            params[key] = value
        
        pa = self.normalize_vpa(params.get('pa', ''))
        pn = params.get('pn', '')
        am = params.get('am', None)
        tn = params.get('tn', '')
        cu = params.get('cu', 'INR')

        score = 0
        reasons = []
        
        if not pa:
            score += 40
            reasons.append("⚠️ Invalid QR: No payee address (pa) found in QR")
        
        if am and user_amt and user_amt > 0:
            try:
                qr_amount = float(am)
                if abs(qr_amount - user_amt) > 0.01:
                    score += 65
                    reasons.append(f"🚨 AMOUNT TAMPERING: QR code forces payment of ₹{qr_amount:.2f}, but you entered ₹{user_amt:.2f}")
            except ValueError:
                pass
        
        suspicious_notes = ['refund', 'cashback', 'reward', 'lottery', 'prize', 'winner']
        if tn:
            tn_lower = tn.lower()
            for sus in suspicious_notes:
                if sus in tn_lower:
                    score += 30
                    reasons.append(f"🚨 Suspicious Note: '{tn}' - Common fraud tactic")
                    break
        
        if cu != 'INR':
            score += 20
            reasons.append(f"⚠️ Unusual Currency: {cu} - UPI typically uses INR")

        return min(score, 100), reasons, pa, pn

    def behavioral_check(self, vpa, amt, username):
        score = 0
        reasons = []
        
        if not username:
            username = "default"
        
        # Initialize user history if needed
        if username not in self.user_history:
            self.user_history[username] = []
        
        if username not in self.vpa_history:
            self.vpa_history[username] = {}
        
        now = datetime.now()
        
        conn = self.get_db_connection()
        norm_vpa = self.normalize_vpa(vpa)
        
        try:
            m_data = conn.execute("SELECT avg_amt FROM merchants WHERE vpa=?", (norm_vpa,)).fetchone()
            past_tx_query = conn.execute(
                "SELECT amt FROM logs WHERE vpa=? AND username=? ORDER BY ts DESC LIMIT 10", 
                (norm_vpa, username)
            ).fetchall()
        except Exception as e:
            print(f"Database query error: {e}")
            m_data = None
            past_tx_query = []
        
        conn.close()
        
        # ========== FIX: Amount exactly 5x merchant average (>= instead of >) ==========
        if m_data and m_data['avg_amt'] and m_data['avg_amt'] > 0:
            avg_amt = m_data['avg_amt']
            if amt >= avg_amt * 5:  # Changed from > to >=
                score += 45
                reasons.append(f"🚨 SUDDEN SPIKE: ₹{amt:.2f} is 5x or higher than merchant average (₹{avg_amt:.2f})")
            elif amt >= avg_amt * 3:  # Changed from > to >=
                score += 25
                reasons.append(f"⚠️ High Amount: ₹{amt:.2f} is 3x or higher than merchant average (₹{avg_amt:.2f})")
        
        # Amount spike vs personal history
        if past_tx_query and len(past_tx_query) >= 2:
            past_amounts = [tx['amt'] for tx in past_tx_query[:5]]
            if past_amounts:
                personal_avg = sum(past_amounts) / len(past_amounts)
                if amt > personal_avg * 4:
                    score += 30
                    reasons.append(f"⚠️ Unusual Amount: Much higher than your usual transactions (avg ₹{personal_avg:.2f})")
        
        # ========== FIX: Rapid transactions across DIFFERENT VPAs ==========
        # Clean old entries (older than 2 minutes)
        cutoff = now - timedelta(minutes=2)
        self.user_history[username] = [t for t in self.user_history[username] if t > cutoff]
        
        # Add current transaction timestamp
        self.user_history[username].append(now)
        
        # Check velocity - counts ALL transactions by this user (regardless of VPA)
        tx_count = len(self.user_history[username])
        
        #if tx_count > 3:
         #     score += 35
          #  reasons.append(f"🚨 RAPID TRANSACTIONS: {tx_count} attempts in last 2 minutes - Possible automated fraud (detected across different VPAs)")
        #elif tx_count > 2:
         #   score += 15
          #  reasons.append(f"⚠️ High Frequency: {tx_count} transactions in last 2 minutes")
        
        # Also track per-VPA for additional detection
        if norm_vpa not in self.vpa_history[username]:
            self.vpa_history[username][norm_vpa] = []
        
        # Clean per-VPA history
        self.vpa_history[username][norm_vpa] = [t for t in self.vpa_history[username][norm_vpa] if t > cutoff]
        self.vpa_history[username][norm_vpa].append(now)
        
        # If rapid on same VPA, add extra penalty
        if len(self.vpa_history[username][norm_vpa]) > 2:
            score += 15
            reasons.append(f"🚨 Rapid payments to SAME VPA: {len(self.vpa_history[username][norm_vpa])} in 2 minutes")
        
        # Round number detection
        if amt > 0 and amt % 1000 == 0 and amt < 10000:
            score += 5
            reasons.append("ℹ️ Round amount detected - Verify carefully")
        
        return min(score, 100), reasons