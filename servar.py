"""
ECU AI Server - منصة مشاركة حلول IMMO OFF
يعمل على: Python 3.8+
المكتبات: pip install flask flask-cors flask-sqlalchemy bcrypt pyjwt
"""

import os
import json
import hashlib
import secrets
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_file
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

app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ecu_platform.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB

# إنشاء مجلد الرفع
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'original'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'immo_off'), exist_ok=True)

db = SQLAlchemy(app)

# ═══════════════════════════════════════════════════════════════════
# قاعدة البيانات (Models)
# ═══════════════════════════════════════════════════════════════════

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    country = db.Column(db.String(50))
    points = db.Column(db.Integer, default=0)
    level = db.Column(db.String(20), default='Beginner')
    files_uploaded = db.Column(db.Integer, default=0)
    files_downloaded = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)


class ECUFile(db.Model):
    __tablename__ = 'ecu_files'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # معلومات الملف
    file_type = db.Column(db.String(20))  # 'original' or 'immo_off'
    file_hash = db.Column(db.String(64), unique=True)  # MD5
    file_size = db.Column(db.Integer)
    file_path = db.Column(db.String(255))
    
    # معلومات الـ ECU
    ecu_type = db.Column(db.String(50))  # Simos 11.1, MED17, etc
    sw_number = db.Column(db.String(50))  # 03E906019D
    hw_number = db.Column(db.String(50))
    car_brand = db.Column(db.String(50))
    car_model = db.Column(db.String(50))
    car_year = db.Column(db.Integer)
    engine_code = db.Column(db.String(20))
    
    # روابط
    pair_id = db.Column(db.Integer, db.ForeignKey('ecu_files.id'))
    
    # إحصائيات
    downloads = db.Column(db.Integer, default=0)
    rating = db.Column(db.Float, default=0.0)
    verified = db.Column(db.Boolean, default=False)
    
    # توقيت
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # ملاحظات
    notes = db.Column(db.Text)


class Pattern(db.Model):
    __tablename__ = 'patterns'
    id = db.Column(db.Integer, primary_key=True)
    
    # النمط
    search_bytes = db.Column(db.LargeBinary)
    replace_bytes = db.Column(db.LargeBinary)
    context_before = db.Column(db.LargeBinary)
    context_after = db.Column(db.LargeBinary)
    
    # المعلومات
    ecu_type = db.Column(db.String(50))
    offset_hint = db.Column(db.Integer)
    
    # إحصائيات
    frequency = db.Column(db.Integer, default=1)
    success_rate = db.Column(db.Float, default=100.0)
    verified_count = db.Column(db.Integer, default=0)
    
    # توقيت
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime)


class Solution(db.Model):
    __tablename__ = 'solutions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    ecu_type = db.Column(db.String(50))
    sw_number = db.Column(db.String(50))
    
    # تفاصيل الحل
    title = db.Column(db.String(200))
    description = db.Column(db.Text)
    patches_json = db.Column(db.Text)  # JSON من الـ patches
    
    # تقييم
    upvotes = db.Column(db.Integer, default=0)
    downloads = db.Column(db.Integer, default=0)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ═══════════════════════════════════════════════════════════════════
# دوال المساعدة
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
            current_user = User.query.get(payload['user_id'])
            if not current_user:
                return jsonify({'error': 'Invalid user'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated


def calculate_level(points):
    if points >= 10000: return 'Master'
    elif points >= 5000: return 'Expert'
    elif points >= 2000: return 'Advanced'
    elif points >= 500: return 'Intermediate'
    else: return 'Beginner'


def calculate_file_hash(file_data):
    return hashlib.md5(file_data).hexdigest()


# ═══════════════════════════════════════════════════════════════════
# API Endpoints - المصادقة
# ═══════════════════════════════════════════════════════════════════

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    
    # التحقق من البيانات
    if not all(k in data for k in ['username', 'email', 'password']):
        return jsonify({'error': 'Missing fields'}), 400
    
    # التحقق من عدم وجود مستخدم
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username exists'}), 400
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email exists'}), 400
    
    # إنشاء المستخدم
    user = User(
        username=data['username'],
        email=data['email'],
        password_hash=hash_password(data['password']),
        country=data.get('country', 'Unknown')
    )
    
    db.session.add(user)
    db.session.commit()
    
    token = generate_token(user.id)
    
    return jsonify({
        'message': 'تم التسجيل بنجاح',
        'token': token,
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
    
    token = generate_token(user.id)
    
    return jsonify({
        'message': 'تم تسجيل الدخول',
        'token': token,
        'user': {
            'id': user.id,
            'username': user.username,
            'points': user.points,
            'level': user.level,
            'files_uploaded': user.files_uploaded
        }
    })


# ═══════════════════════════════════════════════════════════════════
# API Endpoints - الملفات
# ═══════════════════════════════════════════════════════════════════

@app.route('/api/upload', methods=['POST'])
@token_required
def upload_file(current_user):
    """رفع ملف (Original أو IMMO OFF)"""
    
    if 'file' not in request.files:
        return jsonify({'error': 'لا يوجد ملف'}), 400
    
    file = request.files['file']
    
    # المعلومات
    file_type = request.form.get('file_type', 'original')  # 'original' or 'immo_off'
    ecu_type = request.form.get('ecu_type', 'Unknown')
    sw_number = request.form.get('sw_number', '')
    car_brand = request.form.get('car_brand', '')
    car_model = request.form.get('car_model', '')
    car_year = request.form.get('car_year', 0)
    notes = request.form.get('notes', '')
    pair_id = request.form.get('pair_id', None)
    
    # قراءة الملف
    file_data = file.read()
    file_hash = calculate_file_hash(file_data)
    
    # التحقق من عدم وجود الملف مسبقاً
    existing = ECUFile.query.filter_by(file_hash=file_hash).first()
    if existing:
        return jsonify({
            'error': 'الملف موجود مسبقاً',
            'file_id': existing.id
        }), 409
    
    # حفظ الملف
    filename = f"{file_hash}.bin"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_type, filename)
    
    with open(file_path, 'wb') as f:
        f.write(file_data)
    
    # حفظ في DB
    ecu_file = ECUFile(
        user_id=current_user.id,
        file_type=file_type,
        file_hash=file_hash,
        file_size=len(file_data),
        file_path=file_path,
        ecu_type=ecu_type,
        sw_number=sw_number,
        car_brand=car_brand,
        car_model=car_model,
        car_year=int(car_year) if car_year else None,
        notes=notes,
        pair_id=int(pair_id) if pair_id else None
    )
    
    db.session.add(ecu_file)
    
    # نقاط للمستخدم
    if file_type == 'immo_off':
        current_user.points += 50  # 50 نقطة للحل
    else:
        current_user.points += 10  # 10 نقاط للأصلي
    
    current_user.files_uploaded += 1
    current_user.level = calculate_level(current_user.points)
    
    db.session.commit()
    
    return jsonify({
        'message': 'تم الرفع بنجاح',
        'file_id': ecu_file.id,
        'points_earned': 50 if file_type == 'immo_off' else 10,
        'total_points': current_user.points,
        'level': current_user.level
    })


@app.route('/api/upload_pair', methods=['POST'])
@token_required
def upload_pair(current_user):
    """رفع زوج كامل (Original + IMMO OFF) معاً"""
    
    if 'original' not in request.files or 'immo_off' not in request.files:
        return jsonify({'error': 'يجب رفع الملفين'}), 400
    
    original = request.files['original']
    immo_off = request.files['immo_off']
    
    ecu_type = request.form.get('ecu_type', 'Unknown')
    sw_number = request.form.get('sw_number', '')
    car_brand = request.form.get('car_brand', '')
    
    # قراءة الملفين
    orig_data = original.read()
    immo_data = immo_off.read()
    
    if len(orig_data) != len(immo_data):
        return jsonify({'error': 'حجم الملفين مختلف'}), 400
    
    orig_hash = calculate_file_hash(orig_data)
    immo_hash = calculate_file_hash(immo_data)
    
    # حفظ الأصلي
    orig_path = os.path.join(app.config['UPLOAD_FOLDER'], 'original', f"{orig_hash}.bin")
    with open(orig_path, 'wb') as f:
        f.write(orig_data)
    
    orig_file = ECUFile(
        user_id=current_user.id,
        file_type='original',
        file_hash=orig_hash,
        file_size=len(orig_data),
        file_path=orig_path,
        ecu_type=ecu_type,
        sw_number=sw_number,
        car_brand=car_brand
    )
    db.session.add(orig_file)
    db.session.flush()
    
    # حفظ المعدل
    immo_path = os.path.join(app.config['UPLOAD_FOLDER'], 'immo_off', f"{immo_hash}.bin")
    with open(immo_path, 'wb') as f:
        f.write(immo_data)
    
    immo_file = ECUFile(
        user_id=current_user.id,
        file_type='immo_off',
        file_hash=immo_hash,
        file_size=len(immo_data),
        file_path=immo_path,
        ecu_type=ecu_type,
        sw_number=sw_number,
        car_brand=car_brand,
        pair_id=orig_file.id
    )
    db.session.add(immo_file)
    
    # ربط الأصلي بالمعدل
    orig_file.pair_id = immo_file.id
    
    # استخراج الأنماط تلقائياً
    patterns_found = extract_patterns_from_pair(orig_data, immo_data, ecu_type)
    
    for pattern_data in patterns_found:
        # هل النمط موجود؟
        existing = Pattern.query.filter_by(
            search_bytes=pattern_data['search'],
            replace_bytes=pattern_data['replace']
        ).first()
        
        if existing:
            existing.frequency += 1
        else:
            pattern = Pattern(
                search_bytes=pattern_data['search'],
                replace_bytes=pattern_data['replace'],
                context_before=pattern_data['ctx_before'],
                context_after=pattern_data['ctx_after'],
                ecu_type=ecu_type,
                offset_hint=pattern_data['offset']
            )
            db.session.add(pattern)
    
    # نقاط
    current_user.points += 100  # 100 نقطة للزوج الكامل
    current_user.files_uploaded += 2
    current_user.level = calculate_level(current_user.points)
    
    db.session.commit()
    
    return jsonify({
        'message': 'تم رفع الزوج بنجاح',
        'patterns_extracted': len(patterns_found),
        'points_earned': 100,
        'total_points': current_user.points,
        'level': current_user.level
    })


def extract_patterns_from_pair(orig_data, mod_data, ecu_type):
    """استخراج الأنماط من زوج ملفات"""
    patterns = []
    
    # ايجاد الفروقات
    diffs = []
    for i in range(len(orig_data)):
        if orig_data[i] != mod_data[i]:
            diffs.append(i)
    
    if not diffs:
        return []
    
    # تجميع الفروقات
    clusters = []
    current = [diffs[0]]
    for i in range(1, len(diffs)):
        if diffs[i] - current[-1] <= 16:
            current.append(diffs[i])
        else:
            clusters.append(current)
            current = [diffs[i]]
    clusters.append(current)
    
    # استخراج النمط من كل cluster
    for cluster in clusters:
        start = cluster[0]
        end = cluster[-1] + 1
        ctx = 16
        
        patterns.append({
            'offset': start,
            'search': bytes(orig_data[start:end]),
            'replace': bytes(mod_data[start:end]),
            'ctx_before': bytes(orig_data[max(0, start-ctx):start]),
            'ctx_after': bytes(orig_data[end:min(len(orig_data), end+ctx)])
        })
    
    return patterns


@app.route('/api/search', methods=['GET'])
@token_required
def search_files(current_user):
    """البحث عن ملفات IMMO OFF"""
    
    ecu_type = request.args.get('ecu_type', '')
    sw_number = request.args.get('sw_number', '')
    car_brand = request.args.get('car_brand', '')
    
    query = ECUFile.query.filter_by(file_type='immo_off')
    
    if ecu_type:
        query = query.filter(ECUFile.ecu_type.ilike(f'%{ecu_type}%'))
    if sw_number:
        query = query.filter(ECUFile.sw_number.ilike(f'%{sw_number}%'))
    if car_brand:
        query = query.filter(ECUFile.car_brand.ilike(f'%{car_brand}%'))
    
    files = query.order_by(ECUFile.uploaded_at.desc()).limit(50).all()
    
    results = []
    for f in files:
        uploader = User.query.get(f.user_id)
        results.append({
            'id': f.id,
            'ecu_type': f.ecu_type,
            'sw_number': f.sw_number,
            'car_brand': f.car_brand,
            'car_model': f.car_model,
            'car_year': f.car_year,
            'file_size': f.file_size,
            'downloads': f.downloads,
            'rating': f.rating,
            'verified': f.verified,
            'uploaded_at': f.uploaded_at.isoformat(),
            'uploaded_by': uploader.username if uploader else 'Unknown',
            'notes': f.notes
        })
    
    return jsonify({
        'count': len(results),
        'files': results
    })


@app.route('/api/download/<int:file_id>', methods=['GET'])
@token_required
def download_file(current_user, file_id):
    """تحميل ملف"""
    
    ecu_file = ECUFile.query.get_or_404(file_id)
    
    # تحديث الإحصائيات
    ecu_file.downloads += 1
    current_user.files_downloaded += 1
    
    # خصم نقطة للتحميل
    if current_user.points >= 5:
        current_user.points -= 5
    
    db.session.commit()
    
    return send_file(ecu_file.file_path, 
                     as_attachment=True,
                     download_name=f"{ecu_file.sw_number}_{ecu_file.file_type}.bin")


@app.route('/api/patterns', methods=['GET'])
@token_required
def get_patterns(current_user):
    """تحميل قاعدة بيانات الأنماط"""
    
    ecu_type = request.args.get('ecu_type', '')
    
    query = Pattern.query
    if ecu_type:
        query = query.filter(Pattern.ecu_type.ilike(f'%{ecu_type}%'))
    
    patterns = query.order_by(Pattern.frequency.desc()).limit(500).all()
    
    results = []
    for p in patterns:
        results.append({
            'id': p.id,
            'ecu_type': p.ecu_type,
            'search_bytes': p.search_bytes.hex() if p.search_bytes else '',
            'replace_bytes': p.replace_bytes.hex() if p.replace_bytes else '',
            'context_before': p.context_before.hex() if p.context_before else '',
            'context_after': p.context_after.hex() if p.context_after else '',
            'offset_hint': p.offset_hint,
            'frequency': p.frequency,
            'success_rate': p.success_rate
        })
    
    return jsonify({
        'count': len(results),
        'patterns': results
    })


@app.route('/api/stats', methods=['GET'])
def global_stats():
    """إحصائيات عامة"""
    return jsonify({
        'total_users': User.query.count(),
        'total_files': ECUFile.query.count(),
        'total_patterns': Pattern.query.count(),
        'total_solutions': Solution.query.count(),
        'immo_off_files': ECUFile.query.filter_by(file_type='immo_off').count(),
        'top_contributors': [
            {'username': u.username, 'points': u.points, 'level': u.level}
            for u in User.query.order_by(User.points.desc()).limit(10).all()
        ]
    })


@app.route('/api/user/profile', methods=['GET'])
@token_required
def user_profile(current_user):
    """ملف المستخدم"""
    return jsonify({
        'username': current_user.username,
        'email': current_user.email,
        'country': current_user.country,
        'points': current_user.points,
        'level': current_user.level,
        'files_uploaded': current_user.files_uploaded,
        'files_downloaded': current_user.files_downloaded,
        'created_at': current_user.created_at.isoformat()
    })


# ═══════════════════════════════════════════════════════════════════
# الصفحة الرئيسية
# ═══════════════════════════════════════════════════════════════════

@app.route('/')
def home():
    return jsonify({
        'name': 'ECU AI Platform Server',
        'version': '1.0',
        'status': 'running',
        'endpoints': {
            'register': '/api/register',
            'login': '/api/login',
            'upload': '/api/upload',
            'upload_pair': '/api/upload_pair',
            'search': '/api/search',
            'download': '/api/download/<id>',
            'patterns': '/api/patterns',
            'stats': '/api/stats'
        }
    })


# ═══════════════════════════════════════════════════════════════════
# تشغيل السيرفر
# ═══════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("✅ Database created")
        print("🚀 Server starting on http://0.0.0.0:5000")
        print("📡 API documentation: http://localhost:5000/")
    
    app.run(host='0.0.0.0', port=5000, debug=True)