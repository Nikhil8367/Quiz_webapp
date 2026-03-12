import os
import json
import random
import time
import threading
import datetime
from dotenv import load_dotenv
from flask import Flask, request, jsonify, session
from flask_cors import CORS
from pymongo import MongoClient, errors
from bson import ObjectId
import bcrypt
import google.generativeai as genai
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException

# ─────────────────────────────────────────────
# Load environment variables
# ─────────────────────────────────────────────
load_dotenv()

required_env_vars = ['BREVO_API_KEY', 'MONGO_URI', 'GEMINI_API_KEY']
for var in required_env_vars:
    if not os.getenv(var):
        raise EnvironmentError(f"Missing required environment variable: {var}")

MONGO_URI      = os.getenv("MONGO_URI")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
BREVO_API_KEY  = os.getenv("BREVO_API_KEY")
SENDER_EMAIL   = "quizdmn@gmail.com"
SENDER_NAME    = "Quiz Admin"

# ─────────────────────────────────────────────
# Flask app  ← only ONE instance
# ─────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = "a_very_long_random_string_1234567890!@#$%"

# ── CORS fix: allow every origin for all routes, including OPTIONS preflight ──
CORS(app,
     resources={r"/*": {"origins": "*"}},
     supports_credentials=False,          # must be False when origins="*"
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])

# ─────────────────────────────────────────────
# MongoDB
# ─────────────────────────────────────────────
try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    client.server_info()
    db                 = client['login_db']
    users_collection   = db['users']
    scores_collection  = db['scores']
    quizzes_collection = db['quizzes']
    print("✅ MongoDB connected successfully.")
except errors.ServerSelectionTimeoutError as err:
    print("❌ MongoDB connection failed:", err)
    raise SystemExit("Exiting due to MongoDB connection failure.")

# ─────────────────────────────────────────────
# Seed users
# ─────────────────────────────────────────────
preexisting_users = [
    {
        'email':    'nikhil@gvpce.ac.in',
        'password': bcrypt.hashpw('teacher123'.encode(), bcrypt.gensalt()),
        'role':     'teacher'
    }
]
for i in range(323103383001, 323103383071):
    preexisting_users.append({
        'email':    f'{i}@gvpce.ac.in',
        'password': bcrypt.hashpw('student123'.encode(), bcrypt.gensalt()),
        'role':     'student'
    })

for user in preexisting_users:
    if not users_collection.find_one({'email': user['email']}):
        users_collection.insert_one(user)
        print(f"✅ Inserted: {user['email']} ({user['role']})")

# ─────────────────────────────────────────────
# Gemini
# ─────────────────────────────────────────────
genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel("gemini-2.5-flash")

# ─────────────────────────────────────────────
# Brevo (transactional email)
# ─────────────────────────────────────────────
brevo_cfg = sib_api_v3_sdk.Configuration()
brevo_cfg.api_key['api-key'] = BREVO_API_KEY
smtp_api = sib_api_v3_sdk.TransactionalEmailsApi(
    sib_api_v3_sdk.ApiClient(brevo_cfg)
)

# ─────────────────────────────────────────────
# In-memory OTP store + cleanup thread
# ─────────────────────────────────────────────
otp_store          = {}
OTP_EXPIRY_SECONDS = 300

def _cleanup_otps():
    while True:
        now     = time.time()
        expired = [e for e, (_, exp) in otp_store.items() if exp < now]
        for e in expired:
            del otp_store[e]
        time.sleep(60)

threading.Thread(target=_cleanup_otps, daemon=True).start()


# ═════════════════════════════════════════════
# ROUTES
# ═════════════════════════════════════════════

# ── Auth ──────────────────────────────────────

@app.route('/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS':
        return _preflight()

    data     = request.get_json(silent=True) or {}
    email    = data.get('email', '').strip()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'error': 'Missing email or password'}), 400

    user = users_collection.find_one({'email': email})
    if not user:
        return jsonify({'error': 'User not found'}), 404

    if bcrypt.checkpw(password.encode(), user['password']):
        return jsonify({
            'message': 'Login successful',
            'role':    user.get('role', 'student'),
            'email':   email
        }), 200

    return jsonify({'error': 'Incorrect password'}), 401


@app.route('/register', methods=['POST', 'OPTIONS'])
def register():
    if request.method == 'OPTIONS':
        return _preflight()

    data     = request.get_json(silent=True) or {}
    email    = data.get('email', '').strip()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400

    if users_collection.find_one({'email': email}):
        return jsonify({'error': 'User already exists'}), 400

    users_collection.insert_one({
        'email':    email,
        'password': bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    })
    return jsonify({'message': 'User registered successfully'}), 201


@app.route('/reset-password', methods=['POST', 'OPTIONS'])
def reset_password():
    if request.method == 'OPTIONS':
        return _preflight()

    data         = request.get_json(silent=True) or {}
    email        = data.get('email', '').strip()
    new_password = data.get('password', '')

    if not email:
        return jsonify({'success': False, 'message': 'Missing email'}), 400
    if not new_password:
        return jsonify({'success': False, 'message': 'Missing password'}), 400
    if len(new_password) < 6:
        return jsonify({'success': False, 'message': 'Password too short (min 6 chars)'}), 400

    result = users_collection.update_one(
        {'email': email},
        {'$set': {'password': bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())}}
    )
    if result.modified_count == 1:
        return jsonify({'success': True, 'message': 'Password updated successfully'}), 200
    return jsonify({'success': False, 'message': 'Email not found'}), 404


# ── OTP ───────────────────────────────────────

@app.route('/send-otp', methods=['POST', 'OPTIONS'])
def send_otp():
    if request.method == 'OPTIONS':
        return _preflight()

    data  = request.get_json(silent=True) or {}
    email = data.get('email', '').strip()
    if not email:
        return jsonify({'success': False, 'message': 'Missing email'}), 400

    otp    = str(random.randint(100000, 999999))
    expiry = time.time() + OTP_EXPIRY_SECONDS
    otp_store[email] = (otp, expiry)

    email_obj = sib_api_v3_sdk.SendSmtpEmail(
        to=[{"email": email}],
        sender={"name": SENDER_NAME, "email": SENDER_EMAIL},
        subject="Your OTP Code",
        html_content=f"<strong>Your OTP code is: {otp}</strong>"
    )
    try:
        smtp_api.send_transac_email(email_obj)
        return jsonify({'success': True, 'message': 'OTP sent successfully'}), 200
    except ApiException as e:
        print(f"Brevo error: {e}")
        return jsonify({'success': False, 'message': 'Failed to send OTP'}), 500


@app.route('/verify-otp', methods=['POST', 'OPTIONS'])
def verify_otp():
    if request.method == 'OPTIONS':
        return _preflight()

    data         = request.get_json(silent=True) or {}
    email        = data.get('email', '').strip()
    entered_otp  = data.get('otp', '').strip()

    if not email or not entered_otp:
        return jsonify({'success': False, 'message': 'Missing email or OTP'}), 400

    stored = otp_store.get(email)
    if not stored:
        return jsonify({'success': False, 'message': 'No OTP found or expired'}), 401

    otp, expiry = stored
    if time.time() > expiry:
        del otp_store[email]
        return jsonify({'success': False, 'message': 'OTP expired'}), 401

    if entered_otp == otp:
        del otp_store[email]
        return jsonify({'success': True, 'message': 'OTP verified successfully'}), 200

    return jsonify({'success': False, 'message': 'Invalid OTP'}), 401


# ── Quiz generation ───────────────────────────

@app.route('/generate-quiz', methods=['POST', 'OPTIONS'])
def generate_quiz():
    if request.method == 'OPTIONS':
        return _preflight()

    data = request.get_json(silent=True) or {}
    topic        = data.get('topic', 'Python').strip() or 'Python'
    difficulty   = data.get('difficulty', 'medium').strip() or 'medium'
    num_questions = 5
    try:
        num_questions = int(data.get('numQuestions', 5))
    except (TypeError, ValueError):
        pass

    prompt = f"""
Generate exactly {num_questions} multiple choice quiz questions.

Topic: {topic}
Difficulty: {difficulty}

Return ONLY a raw JSON array in this exact format:

[
  {{
    "question": "Question text",
    "options": {{
      "A": "option1",
      "B": "option2",
      "C": "option3",
      "D": "option4"
    }},
    "answer": "A"
  }}
]

Rules:
- answer must be exactly A/B/C/D
- no markdown, no explanation, no extra text
- strict JSON only
"""
    try:
        response = model.generate_content(prompt)
        raw      = response.text.strip().replace("```json", "").replace("```", "").strip()
        questions = json.loads(raw)
    except Exception as e:
        print("Quiz generation error:", e)
        questions = []

    return jsonify({'topic': topic, 'difficulty': difficulty, 'questions': questions}), 200


# ── Quiz CRUD ─────────────────────────────────

@app.route('/api/quizzes', methods=['GET', 'OPTIONS'])
def get_all_quizzes():
    if request.method == 'OPTIONS':
        return _preflight()
    try:
        quizzes = []
        for q in quizzes_collection.find({}):
            q['_id'] = str(q['_id'])
            quizzes.append(q)
        return jsonify(quizzes), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/quizzes', methods=['POST', 'OPTIONS'])
def upload_quiz():
    if request.method == 'OPTIONS':
        return _preflight()

    data = request.get_json(silent=True) or {}
    for field in ['createdBy', 'topic', 'difficulty', 'questions']:
        if field not in data:
            return jsonify({'error': f'Missing field: {field}'}), 400

    quiz = {
        'createdBy':    data['createdBy'],
        'topic':        data['topic'],
        'difficulty':   data['difficulty'],
        'questions':    data['questions'],
        'assignedTo':   data.get('assignedTo', ''),
        'numQuestions': len(data['questions'])
    }
    try:
        quizzes_collection.insert_one(quiz)
        return jsonify({'message': 'Quiz uploaded successfully'}), 201
    except Exception as e:
        return jsonify({'error': 'Database error', 'details': str(e)}), 500


@app.route('/api/quiz/<quiz_id>', methods=['GET', 'OPTIONS'])
def get_quiz_by_id(quiz_id):
    if request.method == 'OPTIONS':
        return _preflight()
    try:
        quiz = quizzes_collection.find_one({'_id': ObjectId(quiz_id)})
        if not quiz:
            return jsonify({'error': 'Quiz not found'}), 404
        quiz['_id'] = str(quiz['_id'])
        return jsonify(quiz), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/quiz/<quiz_id>', methods=['DELETE', 'OPTIONS'])
def delete_quiz(quiz_id):
    if request.method == 'OPTIONS':
        return _preflight()
    try:
        oid          = ObjectId(quiz_id)
        quiz_result  = quizzes_collection.delete_one({'_id': oid})
        if quiz_result.deleted_count == 0:
            return jsonify({'error': 'Quiz not found'}), 404
        scores_result = scores_collection.delete_many({'quizId': oid})
        return jsonify({
            'message':        'Quiz and scores deleted',
            'quiz_deleted':   quiz_result.deleted_count,
            'scores_deleted': scores_result.deleted_count
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/quiz/<quiz_id>/grade', methods=['POST', 'OPTIONS'])
def grade_quiz(quiz_id):
    if request.method == 'OPTIONS':
        return _preflight()
    try:
        data            = request.get_json(silent=True) or {}
        student_answers = data.get('answers', [])
        quiz            = quizzes_collection.find_one({'_id': ObjectId(quiz_id)})
        if not quiz:
            return jsonify({'error': 'Quiz not found'}), 404

        questions = quiz.get('questions', [])
        score     = 0
        results   = []

        for ans in student_answers:
            q_idx          = ans.get('questionIndex')
            student_answer = ans.get('answer')
            if q_idx is None or q_idx >= len(questions):
                continue
            is_correct = (student_answer == questions[q_idx].get('answer'))
            results.append({
                'questionIndex':  q_idx,
                'studentAnswer':  student_answer,
                'isCorrect':      is_correct
            })
            if is_correct:
                score += 1

        return jsonify({'score': score, 'total': len(questions), 'results': results}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/submitScore', methods=['POST', 'OPTIONS'])
def submit_score():
    if request.method == 'OPTIONS':
        return _preflight()
    try:
        data            = request.get_json(silent=True) or {}
        quiz_id         = data.get('quizId')
        student_roll_no = data.get('studentRollNo')
        score           = data.get('score')
        total           = data.get('total')

        if not all([quiz_id, student_roll_no, score is not None, total]):
            return jsonify({'error': 'Missing data'}), 400

        oid = ObjectId(quiz_id)
        if not quizzes_collection.find_one({'_id': oid}):
            return jsonify({'error': 'Invalid quizId'}), 404

        if scores_collection.find_one({'quizId': oid, 'studentRollNo': student_roll_no}):
            return jsonify({'message': 'Score already submitted'}), 409

        scores_collection.insert_one({
            'quizId':        oid,
            'studentRollNo': student_roll_no.strip(),
            'score':         int(score),
            'total':         int(total),
            'submittedAt':   datetime.datetime.utcnow()
        })
        return jsonify({'message': 'Score submitted successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/my-quizzes/<teacher_id>', methods=['GET', 'OPTIONS'])
def get_my_quizzes(teacher_id):
    if request.method == 'OPTIONS':
        return _preflight()
    try:
        quizzes = []
        for q in quizzes_collection.find({'createdBy': teacher_id}):
            q['_id'] = str(q['_id'])
            quizzes.append(q)
        return jsonify(quizzes), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/get-student-scores-by-quiz', methods=['POST', 'OPTIONS'])
def get_student_scores_by_quiz():
    if request.method == 'OPTIONS':
        return _preflight()

    data          = request.get_json(silent=True) or {}
    teacher_email = data.get('teacherEmail', '').strip()
    quiz_id       = data.get('quizId', '').strip()
    roll_prefix   = data.get('studentRollNo', '').strip()

    if not teacher_email or not quiz_id:
        return jsonify({'error': 'Missing data'}), 400

    quiz = quizzes_collection.find_one({'_id': ObjectId(quiz_id), 'createdBy': teacher_email})
    if not quiz:
        return jsonify({'error': 'Quiz not found or not authorized'}), 404

    query = {'quizId': ObjectId(quiz_id)}
    if roll_prefix:
        query['studentRollNo'] = {'$regex': f'^{roll_prefix}'}

    result = []
    for s in scores_collection.find(query):
        result.append({
            'topic':         quiz.get('topic', 'Unknown'),
            'studentRollNo': s['studentRollNo'],
            'score':         s['score'],
            'total':         s['total'],
            'submittedAt':   s['submittedAt'].isoformat()
        })
    return jsonify(result), 200


# ─────────────────────────────────────────────
# Helper: manual preflight response
# ─────────────────────────────────────────────
def _preflight():
    resp = jsonify({'status': 'ok'})
    resp.headers['Access-Control-Allow-Origin']  = '*'
    resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    return resp, 200


# ─────────────────────────────────────────────
if __name__ == '__main__':
    app.run(debug=True)