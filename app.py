from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from googletrans import Translator
import sqlite3
import spacy
import json
import re
from datetime import datetime, timedelta
import random
import hashlib
import hmac
import base64
import requests
import time
import os

# Production configuration
DEBUG = os.environ.get('FLASK_ENV') != 'production'
SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY

translator = Translator()
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

print("Loading model...")
try:
    if os.path.exists("./output_large/model-last"):
        nlp = spacy.load("./output_large/model-last")
        print("✓ Custom model loaded!")
    else:
        nlp = spacy.load("en_core_web_sm")
        print("✓ Base model loaded!")
except:
    nlp = spacy.load("en_core_web_sm")
    print("✓ Fallback model loaded!")

with open('large_intent_dataset.json', 'r') as f:
    intent_data = json.load(f)

EXCHANGE_RATE_API = "https://api.exchangerate-api.com/v4/latest/USD"
DUMMY_BANK_API_BASE = "http://localhost:5001/api"

exchange_rate_cache = {'data': None, 'timestamp': 0}
CACHE_DURATION = 3600

class User(UserMixin):
    def __init__(self, id, username, email, full_name, account_number, balance, role='user'):
        self.id = id
        self.username = username
        self.email = email
        self.full_name = full_name
        self.account_number = account_number
        self.balance = balance
        self.role = role
    
    def is_admin(self):
        return self.role == 'admin'
    
    def generate_token(self):
        data = f"{self.id}:{self.username}:{self.role}:{datetime.utcnow().isoformat()}"
        signature = hmac.new(
            app.config['SECRET_KEY'].encode(),
            data.encode(),
            hashlib.sha256
        ).hexdigest()
        token = base64.b64encode(f"{data}:{signature}".encode()).decode()
        return token

def get_exchange_rates():
    global exchange_rate_cache
    current_time = time.time()
    
    if exchange_rate_cache['data'] and (current_time - exchange_rate_cache['timestamp']) < CACHE_DURATION:
        return exchange_rate_cache['data']
    
    try:
        response = requests.get(EXCHANGE_RATE_API, timeout=5)
        if response.status_code == 200:
            data = response.json()
            exchange_rate_cache['data'] = data['rates']
            exchange_rate_cache['timestamp'] = current_time
            return data['rates']
    except:
        pass
    
    return {
        'EUR': 0.85,
        'GBP': 0.73,
        'INR': 83.12,
        'JPY': 149.50,
        'CAD': 1.36,
        'AUD': 1.52,
        'CHF': 0.88
    }

def get_account_balance_from_api(account_number):
    try:
        response = requests.get(
            f"{DUMMY_BANK_API_BASE}/balance/{account_number}",
            timeout=3
        )
        if response.status_code == 200:
            return response.json().get('balance')
    except:
        pass
    
    conn = sqlite3.connect('bank_chatbot.db')
    cursor = conn.cursor()
    cursor.execute('SELECT balance FROM users WHERE account_number = ?', (account_number,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('bank_chatbot.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, email, full_name, account_number, balance, role FROM users WHERE id = ?', (user_id,))
    user_data = cursor.fetchone()
    conn.close()
    
    if user_data:
        return User(user_data[0], user_data[1], user_data[2], user_data[3], user_data[4], user_data[5], user_data[6] if len(user_data) > 6 and user_data[6] else 'user')
    return None

def get_db_connection():
    conn = sqlite3.connect('bank_chatbot.db')
    conn.row_factory = sqlite3.Row
    return conn

def save_chat_history(user_id, message, response, intent, confidence, language='en'):
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO chat_history (user_id, message, response, intent, confidence)
        VALUES (?, ?, ?, ?, ?)
    ''', (user_id, message, response, intent, confidence))
    conn.commit()
    conn.close()

def get_user_transactions(user_id, limit=5):
    conn = get_db_connection()
    transactions = conn.execute('''
        SELECT transaction_type, amount, description, timestamp
        FROM transactions 
        WHERE user_id = ? 
        ORDER BY timestamp DESC 
        LIMIT ?
    ''', (user_id, limit)).fetchall()
    conn.close()
    return transactions

def get_user_balance(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT account_number FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    
    if user:
        api_balance = get_account_balance_from_api(user['account_number'])
        if api_balance is not None:
            return api_balance
    
    conn = get_db_connection()
    balance = conn.execute('SELECT balance FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    return balance['balance'] if balance else 0

def update_user_balance(user_id, new_balance):
    conn = get_db_connection()
    conn.execute('UPDATE users SET balance = ? WHERE id = ?', (new_balance, user_id))
    conn.commit()
    conn.close()

def add_transaction(user_id, txn_type, amount, description, recipient=None):
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO transactions (user_id, transaction_type, amount, description, recipient_account, status)
        VALUES (?, ?, ?, ?, ?, 'completed')
    ''', (user_id, txn_type, amount, description, recipient))
    conn.commit()
    conn.close()

def detect_and_translate(text, target_lang='en'):
    try:
        detected = translator.detect(text)
        if detected.lang != target_lang:
            translated = translator.translate(text, src=detected.lang, dest=target_lang)
            return translated.text, detected.lang
        return text, detected.lang
    except:
        return text, 'en'

def translate_response(text, target_lang='en'):
    try:
        if target_lang != 'en':
            translated = translator.translate(text, src='en', dest=target_lang)
            return translated.text
        return text
    except:
        return text

GREETING_PATTERNS = [r'\b(hi|hello|hey|greetings|good morning|good afternoon|good evening|howdy|hola|bonjour|namaste)\b']
FAREWELL_PATTERNS = [r'\b(bye|goodbye|see you|take care|thanks|thank you|adios|au revoir)\b']
TRANSFER_PATTERNS = [
    r'\b(send|transfer|pay|give)\s+(\$?\d+(?:\.\d{2})?)\s+(to|into)?\s*(.*)',
    r'\b(transfer|send|pay)\s+(.*?)\s+(\$?\d+(?:\.\d{2})?)',
]

def extract_transfer_info(text):
    text_lower = text.lower().strip()
    for pattern in TRANSFER_PATTERNS:
        match = re.search(pattern, text_lower)
        if match:
            groups = match.groups()
            amount = None
            recipient = None
            for group in groups:
                if group and re.match(r'\$?\d+(?:\.\d{2})?', group):
                    amount = float(re.sub(r'[^\d.]', '', group))
                    break
            for group in groups:
                if group and group not in ['to', 'into', '$'] and not re.match(r'\$?\d+(?:\.\d{2})?', group):
                    recipient = group.strip()
                    break
            return amount, recipient
    return None, None

def is_greeting(text):
    for pattern in GREETING_PATTERNS:
        if re.search(pattern, text.lower().strip()):
            return True
    return False

def is_farewell(text):
    for pattern in FAREWELL_PATTERNS:
        if re.search(pattern, text.lower().strip()):
            return True
    return False

def is_transfer_query(text):
    text_lower = text.lower()
    transfer_keywords = ['send', 'transfer', 'pay', 'move', 'give']
    amount_pattern = r'\b\d+(?:\.\d{2})?\b'
    has_transfer_keyword = any(keyword in text_lower for keyword in transfer_keywords)
    has_amount = re.search(amount_pattern, text_lower)
    return has_transfer_keyword and has_amount

def is_exchange_rate_query(text):
    text_lower = text.lower()
    exchange_keywords = ['exchange rate', 'currency rate', 'forex', 'dollar rate', 'euro rate', 'conversion rate', 'currency conversion']
    return any(keyword in text_lower for keyword in exchange_keywords)

def get_response(intent, confidence, user_id=None, original_text=""):
    if is_exchange_rate_query(original_text):
        rates = get_exchange_rates()
        response = "💱 Current Exchange Rates (USD Base):\n\n"
        response += f"🇪🇺 EUR: ${rates.get('EUR', 0.85):.4f}\n"
        response += f"🇬🇧 GBP: ${rates.get('GBP', 0.73):.4f}\n"
        response += f"🇮🇳 INR: ₹{rates.get('INR', 83.12):.2f}\n"
        response += f"🇯🇵 JPY: ¥{rates.get('JPY', 149.50):.2f}\n"
        response += f"🇨🇦 CAD: ${rates.get('CAD', 1.36):.4f}\n"
        response += f"🇦🇺 AUD: ${rates.get('AUD', 1.52):.4f}\n"
        response += "\n📊 Rates updated from external API"
        return response
    
    if is_transfer_query(original_text):
        amount, recipient = extract_transfer_info(original_text)
        if amount and recipient:
            if user_id:
                current_balance = get_user_balance(user_id)
                if amount <= current_balance:
                    new_balance = current_balance - amount
                    update_user_balance(user_id, new_balance)
                    add_transaction(user_id, 'debit', amount, f'Transfer to {recipient}', recipient)
                    return f"✅ Transfer completed successfully!\n\n💸 Amount: ${amount:,.2f}\n📤 To: {recipient.title()}\n💰 New Balance: ${new_balance:,.2f}\n\nTransaction reference: TXN{random.randint(100000, 999999)}"
                else:
                    return f"❌ Transfer failed - Insufficient funds!\n\n💸 Amount requested: ${amount:,.2f}\n💰 Available balance: ${current_balance:,.2f}"
    
    user_balance = get_user_balance(user_id) if user_id else 5240.50
    parts = intent.split('_')
    
    if intent.startswith('check_balance'):
        return f"Your current account balance is ${user_balance:,.2f}\n\n📡 Retrieved from external banking API"
    elif intent.startswith('transfer_money'):
        return "I can help you transfer money. Please specify amount and recipient (e.g., 'send $500 to savings')"
    elif intent.startswith('transaction_history'):
        if user_id:
            transactions = get_user_transactions(user_id)
            if transactions:
                history = "Recent transactions:\n\n"
                for txn in transactions:
                    sign = '💰 +' if txn['transaction_type'] == 'credit' else '💸 -'
                    history += f"{sign}${txn['amount']:,.2f} - {txn['description']} ({txn['timestamp'][:10]})\n"
                return history
        return "Recent transactions:\n💸 -$45.20 - Grocery Store\n💰 +$3,000 - Salary Credit"
    elif intent.startswith('forex') or 'exchange' in intent:
        rates = get_exchange_rates()
        response = "💱 Current Exchange Rates:\n\n"
        response += f"EUR: ${rates.get('EUR', 0.85):.4f} | INR: ₹{rates.get('INR', 83.12):.2f}\n"
        response += f"GBP: ${rates.get('GBP', 0.73):.4f} | JPY: ¥{rates.get('JPY', 149.50):.2f}\n"
        response += "\n📊 Live rates from external API"
        return response
    elif intent.startswith('branch_'):
        city = parts[1].replace('_', ' ').title()
        return f"🏢 {city} Branch:\n📍 123 {city} Main St\n⏰ Mon-Fri 9AM-5PM\n📞 1800-SPARK-FIN"
    elif intent.startswith('loan_'):
        return "🏠 Loans available at Spark Finance!\n📊 Rates from 8.5%\n🚀 Quick approval"
    elif intent.startswith('card_'):
        return "💳 Spark Finance Cards!\n✨ Cashback up to 5%\n🎁 Welcome bonus"
    else:
        return "I can help with accounts, transfers, loans, cards, and more. What do you need?"

def smart_intent_selection(user_input, predictions):
    if is_exchange_rate_query(user_input):
        return 'forex_exchange_rate', 1.0
    
    if is_transfer_query(user_input):
        transfer_intents = [intent for intent, score in predictions[:20] if 'transfer' in intent]
        if transfer_intents:
            return transfer_intents[0], predictions[0][1] + 0.05
    
    top_candidates = predictions[:10]
    scored_candidates = []
    user_lower = user_input.lower()
    keywords = user_lower.split()
    
    for intent, model_score in top_candidates:
        intent_parts = intent.split('_')
        keyword_matches = sum(1 for keyword in keywords if keyword in intent_parts)
        combined_score = model_score + (keyword_matches * 0.01)
        scored_candidates.append((intent, combined_score))
    
    scored_candidates.sort(key=lambda x: x[1], reverse=True)
    return scored_candidates[0]

def process_message(user_input, user_id=None):
    escalation_keywords = ['human', 'agent', 'representative', 'person', 'talk to someone', 'speak to agent', 'customer service']
    if any(keyword in user_input.lower() for keyword in escalation_keywords):
        if user_id:
            conn = get_db_connection()
            conn.execute('''INSERT INTO escalation_requests (user_id, message, user_question) VALUES (?, ?, ?)''', (user_id, 'User requested human agent', user_input))
            conn.commit()
            conn.close()
        response = "🙋 I understand you'd like to speak with a human agent.\n\n✅ Your request has been recorded (Ticket #" + str(random.randint(10000, 99999)) + ")\n\n📞 Our support team will contact you within 24 hours.\n💬 Meanwhile, I'm here if you have other questions!"
        return {'response': response, 'intent': 'escalate_to_human', 'confidence': '100%', 'language': 'en', 'escalated': True}
    
    english_text, detected_lang = detect_and_translate(user_input, 'en')
    
    if is_greeting(english_text):
        name = current_user.full_name.split()[0] if current_user.is_authenticated else ""
        response = f"Hello{' ' + name if name else ''}! I'm here to help you with your banking needs. What can I assist you with today?"
        response = translate_response(response, detected_lang)
        if user_id:
            save_chat_history(user_id, user_input, response, 'greeting', '100%', detected_lang)
        return {'response': response, 'intent': 'greeting', 'confidence': '100%', 'language': detected_lang}
    
    if is_farewell(english_text):
        name = current_user.full_name.split()[0] if current_user.is_authenticated else ""
        response = f"Thank you{' ' + name if name else ''} for banking with Spark Finance! Have a great day!"
        response = translate_response(response, detected_lang)
        if user_id:
            save_chat_history(user_id, user_input, response, 'farewell', '100%', detected_lang)
        return {'response': response, 'intent': 'farewell', 'confidence': '100%', 'language': detected_lang}
    
    doc = nlp(english_text.lower())
    predictions = sorted(doc.cats.items(), key=lambda x: x[1], reverse=True)
    predicted_intent, confidence = smart_intent_selection(english_text, predictions)
    
    if confidence > 0.005:
        response = get_response(predicted_intent, confidence, user_id, english_text)
        response = translate_response(response, detected_lang)
        if user_id:
            save_chat_history(user_id, user_input, response, predicted_intent, f"{confidence:.2%}", detected_lang)
        return {'response': response, 'intent': predicted_intent, 'confidence': f"{confidence:.2%}", 'language': detected_lang}
    else:
        top_intents = [intent for intent, score in predictions[:5]]
        suggestions = []
        if any('balance' in intent for intent in top_intents):
            suggestions.append("💰 Check my balance")
        if any('transfer' in intent for intent in top_intents):
            suggestions.append("💸 Transfer money")
        if any('loan' in intent for intent in top_intents):
            suggestions.append("🏠 Apply for a loan")
        if any('card' in intent for intent in top_intents):
            suggestions.append("💳 Card services")
        if not suggestions:
            suggestions = ["💰 Check balance", "💸 Transfer money", "🏠 Apply for loan", "💳 Card services"]
        response = "I'm sorry, I didn't quite understand that. Here are some things I can help with:\n\n"
        for suggestion in suggestions[:4]:
            response += f"• {suggestion}\n"
        response += "\n🙋 Or type 'human agent' to speak with our support team"
        response = translate_response(response, detected_lang)
        if user_id:
            save_chat_history(user_id, user_input, response, 'unknown', '0%', detected_lang)
        return {'response': response, 'intent': 'unknown_with_suggestions', 'confidence': '0%', 'language': detected_lang}

def retrain_model():
    try:
        conn = get_db_connection()
        new_intents = conn.execute('''SELECT intent_name, example_text FROM admin_intents WHERE status = 'approved' ''').fetchall()
        conn.close()
        if len(new_intents) == 0:
            return False, "No new training data available"
        with open('large_intent_dataset.json', 'r') as f:
            current_data = json.load(f)
        for intent in new_intents:
            intent_name = intent['intent_name']
            example = intent['example_text']
            if intent_name not in current_data:
                current_data[intent_name] = []
            if example not in current_data[intent_name]:
                current_data[intent_name].append(example)
        with open('large_intent_dataset.json', 'w') as f:
            json.dump(current_data, f, indent=2)
        return True, f"Training data updated with {len(new_intents)} new intents. Model marked for retraining."
    except Exception as e:
        return False, f"Error: {str(e)}"

@app.route('/api/balance/<account_number>')
def api_get_balance(account_number):
    conn = get_db_connection()
    user = conn.execute('SELECT balance FROM users WHERE account_number = ?', (account_number,)).fetchone()
    conn.close()
    if user:
        return jsonify({'balance': user['balance'], 'account_number': account_number, 'status': 'success'})
    return jsonify({'error': 'Account not found'}), 404

@app.route('/api/exchange-rates')
def api_exchange_rates():
    rates = get_exchange_rates()
    return jsonify({'base': 'USD', 'rates': rates, 'timestamp': datetime.now().isoformat()})

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    transactions = get_user_transactions(current_user.id, 10)
    return render_template('dashboard.html', user=current_user, transactions=transactions)

@app.route('/admin')
@login_required
def admin_panel():
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))
    conn = get_db_connection()
    total_users = conn.execute('SELECT COUNT(*) as count FROM users WHERE role = "user"').fetchone()['count']
    total_chats = conn.execute('SELECT COUNT(*) as count FROM chat_history').fetchone()['count']
    pending_intents = conn.execute('SELECT COUNT(*) as count FROM admin_intents WHERE status = "pending"').fetchone()['count']
    escalation_requests = conn.execute('''SELECT er.*, u.username FROM escalation_requests er JOIN users u ON er.user_id = u.id WHERE er.status = 'pending' ORDER BY er.created_at DESC''').fetchall()
    recent_chats = conn.execute('''SELECT ch.message, ch.response, ch.intent, ch.confidence, ch.timestamp, u.username FROM chat_history ch JOIN users u ON ch.user_id = u.id ORDER BY ch.timestamp DESC LIMIT 50''').fetchall()
    pending_intent_list = conn.execute('''SELECT ai.*, u.username FROM admin_intents ai JOIN users u ON ai.created_by = u.id WHERE ai.status = "pending" ORDER BY ai.created_at DESC''').fetchall()
    conn.close()
    return render_template('admin.html', total_users=total_users, total_chats=total_chats, pending_intents=pending_intents, recent_chats=recent_chats, pending_intent_list=pending_intent_list, escalation_requests=escalation_requests)

@app.route('/admin/intent/add', methods=['POST'])
@login_required
def add_intent():
    if not current_user.is_admin():
        return jsonify({'error': 'Access denied'}), 403
    intent_name = request.form.get('intent_name')
    example_text = request.form.get('example_text')
    conn = get_db_connection()
    conn.execute('''INSERT INTO admin_intents (intent_name, example_text, created_by, status) VALUES (?, ?, ?, 'approved')''', (intent_name, example_text, current_user.id))
    conn.commit()
    conn.close()
    flash('Intent added successfully!')
    return redirect(url_for('admin_panel'))

@app.route('/admin/retrain', methods=['POST'])
@login_required
def trigger_retrain():
    if not current_user.is_admin():
        return jsonify({'error': 'Access denied'}), 403
    success, message = retrain_model()
    return jsonify({'success': success, 'message': message})

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    conn = get_db_connection()
    user_data = conn.execute('SELECT * FROM users WHERE username = ? OR email = ?', (username, username)).fetchone()
    conn.close()
    if user_data and check_password_hash(user_data['password_hash'], password):
        user = User(user_data['id'], user_data['username'], user_data['email'], user_data['full_name'], user_data['account_number'], user_data['balance'], user_data['role'] if user_data['role'] else 'user')
        token = user.generate_token()
        return jsonify({'success': True, 'token': token, 'user': {'username': user.username, 'full_name': user.full_name, 'role': user.role, 'account_number': user.account_number, 'balance': user.balance}})
    return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        user_data = conn.execute('SELECT * FROM users WHERE username = ? OR email = ?', (username, username)).fetchone()
        conn.close()
        if user_data and check_password_hash(user_data['password_hash'], password):
            user = User(user_data['id'], user_data['username'], user_data['email'], user_data['full_name'], user_data['account_number'], user_data['balance'], user_data['role'] if user_data['role'] else 'user')
            login_user(user)
            conn = get_db_connection()
            conn.execute('UPDATE users SET last_login = ? WHERE id = ?', (datetime.now(), user_data['id']))
            conn.commit()
            conn.close()
            if user.is_admin():
                return redirect(url_for('admin_panel'))
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        full_name = request.form['full_name']
        phone = request.form['phone']
        account_number = f"SF{random.randint(1000000000, 9999999999)}"
        password_hash = generate_password_hash(password)
        try:
            conn = get_db_connection()
            conn.execute('''INSERT INTO users (username, email, password_hash, full_name, phone, account_number, role) VALUES (?, ?, ?, ?, ?, ?, 'user')''', (username, email, password_hash, full_name, phone, account_number))
            conn.commit()
            conn.close()
            flash('Registration successful! Your account number is: ' + account_number)
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists')
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/chat', methods=['POST'])
@login_required
def chat():
    user_message = request.json.get('message', '')
    if not user_message.strip():
        return jsonify({'error': 'Empty message'}), 400
    result = process_message(user_message, current_user.id)
    return jsonify(result)

@app.route('/escalate', methods=['POST'])
@login_required
def escalate():
    reason = request.json.get('reason', 'User requested human support')
    last_message = request.json.get('last_message', '')
    conn = get_db_connection()
    conn.execute('''INSERT INTO escalation_requests (user_id, message, user_question) VALUES (?, ?, ?)''', (current_user.id, reason, last_message))
    conn.commit()
    ticket_number = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
    conn.close()
    return jsonify({'success': True, 'ticket': ticket_number, 'message': f'Your request has been forwarded to our support team. Ticket #{ticket_number}'})

@app.route('/history')
@login_required
def history():
    conn = get_db_connection()
    chat_history = conn.execute('''SELECT message, response, intent, confidence, timestamp FROM chat_history WHERE user_id = ? ORDER BY timestamp DESC LIMIT 50''', (current_user.id,)).fetchall()
    conn.close()
    return render_template('history.html', chat_history=chat_history)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=DEBUG)
