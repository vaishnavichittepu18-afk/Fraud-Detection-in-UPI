import re
import sqlite3
from datetime import datetime, timedelta
from difflib import SequenceMatcher

class FraudEngine:
    def __init__(self):
        # --- INITIALIZATION BLOCK ---
        # Tracks live transaction velocity per user and per-VPA for anomaly detection
        self.user_history = {}      
        self.vpa_history = {}       
        
        # Official corporate brands used to detect brand spoofing / impersonation
        self.official_brands = ['amazon', 'flipkart', 'zomato', 'swiggy', 'paytm', 
                                'phonepe', 'googlepay', 'sbi', 'hdfc', 'icici']
        
        # Suspicious keywords commonly tied to phishing, social engineering, and rewards
        self.suspicious_keywords = ['verify', 'reward', 'cashback', 'secure', 'support', 
                                    'help', 'customer', 'care', 'refund', 'prize', 
                                    'winner', 'lottery', 'gift', 'voucher']

   
    def get_db_connection(self):
        # --- DATABASE CONNECTION BLOCK ---
        # Opens and returns a connection to the local SQLite database with Row Factory enabled
        conn = sqlite3.connect('system.db')
        conn.row_factory = sqlite3.Row
        return conn
    def normalize_vpa(self, text):
        # --- VPA NORMALIZATION BLOCK ---
        # Strips whitespaces, converts to lowercase, and removes illegal characters from a VPA string
        if not text:
            return ""
        text = str(text).lower().strip()
        text = re.sub(r'[^\w@.-]', '', text)
        return text

    def extract_vpa_from_qr(self, payload):
        # --- QR EXTRACTION BLOCK ---
        # Parses the 'pa=' parameter out of a raw UPI QR string payload
        if not payload:
            return None
        match = re.search(r'pa=([^&]+)', payload)
        if match:
            return self.normalize_vpa(match.group(1))
        return None

    def check_self_payment(self, vpa, username):
        # --- SELF-PAYMENT DETECTION BLOCK ---
        # Prevents users from sending funds to their own handles/usernames
        if not vpa or not username:
            return False
        
        norm_vpa = self.normalize_vpa(vpa)
        norm_username = username.lower()
        vpa_username = norm_vpa.split('@')[0]
        
        if vpa_username == norm_username:
            return True
        
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
        # --- VPA RISK ASSESSMENT BLOCK ---
        # Evaluates structural validity, blacklists, spoofing, and typosquatting for a given VPA[cite: 2]
        norm_vpa = self.normalize_vpa(vpa)
        if not norm_vpa:
            return 0, ["No VPA provided"]
        
        score = 0
        reasons = []
        
        # Format Check: Checks if the '@' symbol is missing
        if '@' not in norm_vpa:
            return 100, ["REJECTED: Invalid UPI VPA format - Missing '@' symbol (e.g., username@bank)"]
        
        # Self-Payment Prevention Rule
        if username and self.check_self_payment(norm_vpa, username):
            return 100, ["SELF-PAYMENT NOT ALLOWED: You cannot send money to yourself"]
        
        if len(norm_vpa.split('@')[0]) < 2:
            score += 30
            reasons.append("Suspicious VPA - Username too short")
        
        conn = self.get_db_connection()
        
        # Database lookups for merchant registry, logs, reports, and blocklists
        merchant = conn.execute("SELECT name, trust_score FROM merchants WHERE vpa=?", (norm_vpa,)).fetchone()
        past_tx = conn.execute("SELECT COUNT(*), AVG(score) FROM logs WHERE vpa=?", (norm_vpa,)).fetchone()
        report_count = conn.execute("SELECT COUNT(*) as count FROM reports WHERE vpa=?", (norm_vpa,)).fetchone()
        report_count = report_count[0] if report_count else 0
        blocked = conn.execute("SELECT * FROM blocked_vpas WHERE vpa=?", (norm_vpa,)).fetchone()
        
        conn.close()
        
        # Rule: Automatically reject globally blacklisted/blocked VPAs
        if blocked:
            return 100, ["🚨 This VPA has been BLOCKED due to multiple fraud reports!"]
        
        # Rule: Reward verified business entities with a safety score discount
        if merchant:
            return -50, [f"✓ Verified Merchant: {merchant['name']} (Trust Score: {merchant['trust_score']}/100)"]
        
        # Rule: Reward known, safe peer contacts with established transaction histories
        if past_tx and past_tx[0] >= 2:
            avg_score = past_tx[1] if past_tx[1] else 0
            if avg_score < 30:
                return -30, [f"✓ Known Contact: Recognized from {past_tx[0]} previous safe transactions"]
        
        # Rule: Flag VPAs flagged repeatedly by other users
        if report_count >= 2:
            score += 40
            reasons.append(f"⚠️ This VPA has been reported {report_count} times for suspicious activity")
        
        # Rule: Penalize unrecognized, unverified personal handles acting as merchants
        score += 35
        reasons.append("⚠️ Unverified Account: This VPA is not in the verified business registry")
        
        # Rule: Detect social engineering keywords inside the VPA prefix
        vpa_prefix = norm_vpa.split('@')[0]
        for keyword in self.suspicious_keywords:
            if keyword in vpa_prefix:
                score += 25
                reasons.append(f"🚨 Suspicious Keyword: '{keyword}' found in VPA - Common fraud pattern")
                break
        
        # Rule: Detect brand impersonation using fuzzy matching similarity ratios
        for brand in self.official_brands:
            similarity = SequenceMatcher(None, vpa_prefix, brand).ratio()
            if brand in vpa_prefix or similarity > 0.75:
                if vpa_prefix != brand:
                    score += 55
                    reasons.append(f"🚨 BRAND SPOOFING: Account mimics '{brand.upper()}' but is NOT the official VPA!")
                    break
        
        # Rule: Catch potential typosquatting using numeric characters in business names
        if re.search(r'\d+', vpa_prefix) and len(vpa_prefix) > 5:
            score += 15
            reasons.append("⚠️ Suspicious Pattern: Numbers in merchant name - Possible typosquatting")
        
        # Rule: Flag consumer handles used for high-risk corporate transaction flows
        personal_suffixes = ['@sbi', '@ybl', '@okaxis', '@oksbi', '@paytm', '@icici', '@hdfc']
        if any(norm_vpa.endswith(suffix) for suffix in personal_suffixes):
            score += 10
            reasons.append("⚠️ Personal Account: Higher risk for merchant transactions")
        
        return min(score, 100), reasons

    def analyze_qr_deep(self, payload, user_amt):
        # --- DEEP QR PAYLOAD ANALYSIS BLOCK ---
        # Decodes QR URI parameters to scan for amount manipulation, currency anomalies, and scam notes[cite: 2]
        if not payload:
            return 0, [], None, ""

        # Rule: Validate URI protocol header to block arbitrary phishing links
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
        
        # NEW SCAM VECTOR: Collect Request (Reverse UPI Scam) detection
        tr_mode = params.get('mode', '').lower()
        if 'collect' in payload.lower() or tr_mode == '02' or params.get('sign') == 'collect':
            return 100, ["🚨 COLLECT REQUEST WARNING: This is a reverse payment request! Entering your PIN will DEBIT your account, not credit it."], pa, pn

        score = 0
        reasons = []
        
        if not pa:
            score += 40
            reasons.append("⚠️ Invalid QR: No payee address (pa) found in QR")
        
        # =========================================================================
        # NEW SCAM VECTOR: QR-on-QR / Standee Overlay & Sticker Swap Detection
        # =========================================================================
        # Scammers paste a fake QR sticker (with a personal VPA handle) on top of a shop standee.
        # Check if the payee name (pn) looks like a business, but the VPA uses a personal/mobile handle 
        # and is missing from the system's verified merchant database.
        if pn and pa:
            conn = self.get_db_connection()
            is_verified = conn.execute("SELECT 1 FROM merchants WHERE vpa=?", (pa,)).fetchone()
            conn.close()
            
            # Check if VPA looks like a personal identifier (contains numbers or mobile patterns, or uses personal bank handles)
            is_personal_vpa = bool(re.search(r'\d{8,}', pa) or any(pa.endswith(s) for s in ['@ybl', '@paytm', '@oksbi', '@okaxis']))
            
            # If the QR claims a business/store name in 'pn' but resolves to an unverified personal handle
            if is_personal_vpa and not is_verified:
                score += 60
                reasons.append(f"🚨 STANDEE SWAP / QR OVERLAY DETECTED: QR claims payee name '{pn}', but resolves to an unverified personal handle ({pa}). Verify if a physical sticker was pasted over the store standee!")

        # Rule: Check if embedded amount fields inside the QR differ from user input (Amount Tampering)
        if am and user_amt and user_amt > 0:
            try:
                qr_amount = float(am)
                if abs(qr_amount - user_amt) > 0.01:
                    score += 65
                    reasons.append(f"🚨 AMOUNT TAMPERING: QR code forces payment of ₹{qr_amount:.2f}, but you entered ₹{user_amt:.2f}")
            except ValueError:
                pass
        
        # Rule: Flag phishing keywords inside the transaction notes (tn)
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
        # --- BEHAVIORAL & VELOCITY ANALYSIS BLOCK ---
        # Benchmarks transaction amounts against averages and monitors rapid-fire sending frequency[cite: 2]
        score = 0
        reasons = []
        
        if not username:
            username = "default"
        
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
            
            # SCAM VECTOR: Fake Accidental Overpayment / Refund Verification
            incoming_credits = conn.execute(
                "SELECT COUNT(*) as count FROM logs WHERE username=? AND vpa=? AND status='Safe'", 
                (username, norm_vpa)
            ).fetchone()['count']
            
        except Exception as _e:
            m_data = None
            past_tx_query = []
            incoming_credits = 1
        
        conn.close()
        
        # Rule: Trigger fraud alerts if sending money to a new VPA claiming a "refund" with no actual transaction history
        if incoming_credits == 0 and amt > 1000:
            score += 35
            reasons.append(f"⚠️ REFUND SCAM WARNING: Attempting to pay ₹{amt:.2f} to a VPA with zero prior payment history. Verify if you actually received funds first!")
        
        # Rule: Flag sudden spikes >= 5x or >= 3x the standard merchant average amount[cite: 2]
        if m_data and m_data['avg_amt'] and m_data['avg_amt'] > 0:
            avg_amt = m_data['avg_amt']
            if amt >= avg_amt * 5:
                score += 45
                reasons.append(f"🚨 SUDDEN SPIKE: ₹{amt:.2f} is 5x or higher than merchant average (₹{avg_amt:.2f})")
            elif amt >= avg_amt * 3:
                score += 25
                reasons.append(f"⚠️ High Amount: ₹{amt:.2f} is 3x or higher than merchant average (₹{avg_amt:.2f})")
        
        # Rule: Flag amounts significantly higher than the user's personal historical average[cite: 2]
        if past_tx_query and len(past_tx_query) >= 2:
            past_amounts = [tx['amt'] for tx in past_tx_query[:5]]
            if past_amounts:
                personal_avg = sum(past_amounts) / len(past_amounts)
                if amt > personal_avg * 4:
                    score += 30
                    reasons.append(f"⚠️ Unusual Amount: Much higher than your usual transactions (avg ₹{personal_avg:.2f})")
        
        # Time-window cleaning (2 minutes rolling threshold) for velocity metrics[cite: 2]
        cutoff = now - timedelta(minutes=2)
        self.user_history[username] = [t for t in self.user_history[username] if t > cutoff]
        self.user_history[username].append(now)
        
        # Rule: Track rapid-fire repeated payment attempts directed to the exact same VPA[cite: 2]
        if norm_vpa not in self.vpa_history[username]:
            self.vpa_history[username][norm_vpa] = []
        
        self.vpa_history[username][norm_vpa] = [t for t in self.vpa_history[username][norm_vpa] if t > cutoff]
        self.vpa_history[username][norm_vpa].append(now)
        
        if len(self.vpa_history[username][norm_vpa]) > 2:
            score += 15
            reasons.append(f"🚨 Rapid payments to SAME VPA: {len(self.vpa_history[username][norm_vpa])} in 2 minutes")
        
        # Rule: Note round amounts that can indicate automated bot testing or bulk scams[cite: 2]
        if amt > 0 and amt % 1000 == 0 and amt < 10000:
            score += 5
            reasons.append("ℹ️ Round amount detected - Verify carefully")
        
        return min(score, 100), reasons
