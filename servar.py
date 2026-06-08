"""
ECU AI Server - Full Version
=============================
يدعم: تسجيل دخول + رفع أنماط + بحث ذكي + تقييم
"""

import os
import json
import hashlib
import secrets
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import jwt
from functools import wraps

# ═══════════════════════════════════════════════════════════════════
# الإعدادات
# ═══════════════════════════════════════════════════════════════════

app = Flask(__name__)
CORS(app)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ecu_ai.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

db = SQLAlchemy(app)


# ═══════════════════════════════════════════════════════════════════
# قاعدة البيانات
# ═══════════════════════════════════════════════════════════════════

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    country = db.Column(db.String(50), default='')
    
    points = db.Column(db.Integer, default=0)
    level = db.Column(db.String(20), default='Beginner')
    
    patterns_uploaded = db.Column(db.Integer, default=0)
    patterns_used = db.Column(db.Integer, default=0)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)


class Pattern(db.Model):
    __tablename__ = 'patterns'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    name = db.Column(db.String(200))
    description = db.Column(db.Text, default='')
    ecu_type = db.Column(db.String(50), default='')
    sw_number = db.Column(db.String(50), default='')
    car_brand = db.Column(db.String(50), default='')
    
    file_size = db.Column(db.Integer)
    differences_json = db.Column(db.Text)
    original_signature = db.Column(db.String(64))
    
    times_used = db.Column(db.Integer, default=0)
    success_count = db.Column(db.Integer, default=0)
    failure_count = db.Column(db.Integer, default=0)
    success_rate = db.Column(db.Float, default=0)
    
    rating_sum = db.Column(db.Float, default=0)
    rating_count = db.Column(db.Integer, default=0)
    rating_avg = db.Column(db.Float, default=0)
    
    verified = db.Column(db.Boolean, default=False)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class PatternUsage(db.Model):
    __tablename__ = 'pattern_usage'
    id = db.Column(db.Integer, primary_key=True)
    pattern_id = db.Column(db.Integer, db.ForeignKey('patterns.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    success = db.Column(db.Boolean)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ═══════════════════════════════════════════════════════════════════
# دوال مساعدة
# ═══════════════════════════════════════════════════════════════════

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def generate_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(days=30)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'Token required'}), 401
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user = User.query.get(payload['user_id'])
            if not user:
                return jsonify({'error': 'Invalid user'}), 401
        except:
            return jsonify({'error': 'Invalid token'}), 401
        return f(user, *args, **kwargs)
    return decorated

def calculate_level(points):
    if points >= 50000: return 'Legend'
    elif points >= 25000: return 'Master'
    elif points >= 10000: return 'Expert'
    elif points >= 5000: return 'Advanced'
    elif points >= 2000: return 'Pro'
    elif points >= 500: return 'Intermediate'
    return 'Beginner'

def add_points(user, points):
    user.points += points
    user.level = calculate_level(user.points)


# ═══════════════════════════════════════════════════════════════════
# الصفحة الرئيسية
# ═══════════════════════════════════════════════════════════════════

@app.route('/')
def home():
    return jsonify({
        'name': 'ECU AI Platform Server',
        'version': '2.0',
        'status': 'running',
        'stats': {
            'users': User.query.count(),
            'patterns': Pattern.query.count(),
            'total_usage': PatternUsage.query.count()
        }
    })


# ═══════════════════════════════════════════════════════════════════
# المصادقة
# ═══════════════════════════════════════════════════════════════════

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    if not all(k in data for k in ['username', 'email', 'password']):
        return jsonify({'error': 'Missing fields'}), 400
    
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username exists'}), 400
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email exists'}), 400
    
    user = User(
        username=data['username'],
        email=data['email'],
        password_hash=hash_password(data['password']),
        country=data.get('country', '')
    )
    db.session.add(user)
    db.session.commit()
    
    return jsonify({
        'message': 'تم التسجيل',
        'token': generate_token(user.id),
        'user': {
            'id': user.id,
            'username': user.username,
            'points': user.points,
            'level': user.level
        }
    }), 201


@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data.get('username')).first()
    
    if not user or not verify_password(data.get('password', ''), user.password_hash):
        return jsonify({'error': 'بيانات خاطئة'}), 401
    
    user.last_login = datetime.utcnow()
    db.session.commit()
    
    return jsonify({
        'message': 'تم الدخول',
        'token': generate_token(user.id),
        'user': {
            'id': user.id,
            'username': user.username,
            'points': user.points,
            'level': user.level,
            'patterns_uploaded': user.patterns_uploaded
        }
    })


@app.route('/api/user/profile', methods=['GET'])
@token_required
def profile(current_user):
    return jsonify({
        'username': current_user.username,
        'email': current_user.email,
        'country': current_user.country,
        'points': current_user.points,
        'level': current_user.level,
        'patterns_uploaded': current_user.patterns_uploaded,
        'patterns_used': current_user.patterns_used,
        'created_at': current_user.created_at.isoformat()
    })


# ═══════════════════════════════════════════════════════════════════
# الأنماط
# ═══════════════════════════════════════════════════════════════════

@app.route('/api/patterns/upload', methods=['POST'])
@token_required
def upload_pattern(current_user):
    data = request.json
    
    required = ['name', 'differences', 'file_size', 'original_signature']
    if not all(k in data for k in required):
        return jsonify({'error': 'بيانات ناقصة'}), 400
    
    differences = data['differences']
    if not differences:
        return jsonify({'error': 'لا توجد اختلافات'}), 400
    
    # فحص التكرار
    existing = Pattern.query.filter_by(
        original_signature=data['original_signature'],
        file_size=data['file_size']
    ).first()
    
    if existing:
        existing.times_used += 1
        db.session.commit()
        return jsonify({
            'message': 'النمط موجود مسبقاً',
            'pattern_id': existing.id,
            'is_new': False
        })
    
    # إنشاء جديد
    pattern = Pattern(
        user_id=current_user.id,
        name=data['name'],
        description=data.get('description', ''),
        ecu_type=data.get('ecu_type', ''),
        sw_number=data.get('sw_number', ''),
        car_brand=data.get('car_brand', ''),
        file_size=data['file_size'],
        differences_json=json.dumps(differences),
        original_signature=data['original_signature']
    )
    db.session.add(pattern)
    
    # نقاط
    points = 50 + min(len(differences) * 2, 100)
    add_points(current_user, points)
    current_user.patterns_uploaded += 1
    
    db.session.commit()
    
    return jsonify({
        'message': '✅ تم الرفع بنجاح',
        'pattern_id': pattern.id,
        'is_new': True,
        'points_earned': points,
        'total_points': current_user.points,
        'level': current_user.level
    })


@app.route('/api/patterns/search', methods=['POST'])
@token_required
def search_patterns(current_user):
    data = request.json
    file_size = data.get('file_size')
    signature = data.get('signature')
    sample_bytes = data.get('sample_bytes', {})
    
    if not file_size or not signature:
        return jsonify({'error': 'بيانات ناقصة'}), 400
    
    patterns = Pattern.query.filter_by(file_size=file_size).all()
    
    if not patterns:
        return jsonify({'count': 0, 'patterns': []})
    
    matching = []
    
    for pattern in patterns:
        try:
            differences = json.loads(pattern.differences_json)
            
            # تطابق التوقيع
            signature_match = (pattern.original_signature == signature)
            
            # حساب التطابق
            score = 0
            total = 0
            for diff in differences:
                offset = str(diff['offset'])
                if offset in sample_bytes:
                    total += 1
                    if sample_bytes[offset] == diff['original']:
                        score += 1
            
            match_percent = (score / total * 100) if total > 0 else 0
            if signature_match:
                match_percent = 100
            
            if match_percent > 30 or signature_match:
                user = User.query.get(pattern.user_id)
                matching.append({
                    'id': pattern.id,
                    'name': pattern.name,
                    'description': pattern.description,
                    'ecu_type': pattern.ecu_type,
                    'sw_number': pattern.sw_number,
                    'car_brand': pattern.car_brand,
                    'differences_count': len(differences),
                    'differences': differences,
                    'match_percent': match_percent,
                    'signature_match': signature_match,
                    'verified': pattern.verified,
                    'times_used': pattern.times_used,
                    'success_rate': pattern.success_rate,
                    'rating_avg': pattern.rating_avg,
                    'rating_count': pattern.rating_count,
                    'uploaded_by': user.username if user else 'Unknown'
                })
        except:
            continue
    
    matching.sort(key=lambda x: (x['signature_match'], x['match_percent'],
                                  x['success_rate']), reverse=True)
    
    return jsonify({
        'count': len(matching),
        'patterns': matching[:10]
    })


@app.route('/api/patterns/<int:pattern_id>/feedback', methods=['POST'])
@token_required
def pattern_feedback(current_user, pattern_id):
    data = request.json
    pattern = Pattern.query.get_or_404(pattern_id)
    
    success = data.get('success', False)
    
    usage = PatternUsage(
        pattern_id=pattern_id,
        user_id=current_user.id,
        success=success
    )
    db.session.add(usage)
    
    pattern.times_used += 1
    if success:
        pattern.success_count += 1
        original_user = User.query.get(pattern.user_id)
        if original_user and original_user.id != current_user.id:
            add_points(original_user, 10)
    else:
        pattern.failure_count += 1
    
    total = pattern.success_count + pattern.failure_count
    if total > 0:
        pattern.success_rate = (pattern.success_count / total) * 100
    
    if pattern.success_count >= 5:
        pattern.verified = True
    
    current_user.patterns_used += 1
    db.session.commit()
    
    return jsonify({
        'message': 'شكراً',
        'pattern_stats': {
            'times_used': pattern.times_used,
            'success_rate': pattern.success_rate,
            'verified': pattern.verified
        }
    })


@app.route('/api/patterns/list', methods=['GET'])
@token_required
def list_patterns(current_user):
    sort_by = request.args.get('sort', 'rating')
    
    query = Pattern.query
    if sort_by == 'rating':
        query = query.order_by(Pattern.rating_avg.desc())
    elif sort_by == 'usage':
        query = query.order_by(Pattern.times_used.desc())
    else:
        query = query.order_by(Pattern.created_at.desc())
    
    patterns = query.limit(50).all()
    
    results = []
    for p in patterns:
        user = User.query.get(p.user_id)
        results.append({
            'id': p.id,
            'name': p.name,
            'ecu_type': p.ecu_type,
            'sw_number': p.sw_number,
            'times_used': p.times_used,
            'success_rate': p.success_rate,
            'verified': p.verified,
            'uploaded_by': user.username if user else 'Unknown'
        })
    
    return jsonify({'count': len(results), 'patterns': results})


@app.route('/api/stats', methods=['GET'])
def global_stats():
    return jsonify({
        'total_users': User.query.count(),
        'total_patterns': Pattern.query.count(),
        'verified_patterns': Pattern.query.filter_by(verified=True).count(),
        'total_usage': PatternUsage.query.count(),
        'top_contributors': [
            {'username': u.username, 'points': u.points, 'level': u.level,
             'patterns': u.patterns_uploaded}
            for u in User.query.order_by(User.points.desc()).limit(10).all()
        ]
    })


# ═══════════════════════════════════════════════════════════════════
# التشغيل
# ═══════════════════════════════════════════════════════════════════

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
