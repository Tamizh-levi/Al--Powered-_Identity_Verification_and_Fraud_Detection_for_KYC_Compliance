import os
import re
import json
import mysql.connector
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from datetime import datetime
import random 
from typing import Dict, Any 

# OCR / name matching imports (must exist in your project)
from ocr_utils import perform_ocr, extract_aadhaar, extract_pan_with_link, extract_driving_license, check_image_quality
from name_match import compare_names

# NLP / text understanding imports
from smart_text_utils import check_text_manipulation, normalize_name, normalize_address, check_complex_patterns 

# NEW: Face Recognition Module Import
from face_matcher import FaceMatcher 

# ---------- Config ----------
app = Flask(__name__)
CORS(app)   # allow all origins by default (adjust for production)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Replace with your DB credentials
db_config = {
    "host": "localhost",
    "user": "root",
    "password": "s.tamizh@2005",
    "database": "smart_kyc",
    "auth_plugin": "mysql_native_password"
}

# Initialize Face Matcher (NEW)
face_matcher = FaceMatcher()


# ---------- Helpers ----------
def get_db():
    try:
        return mysql.connector.connect(**db_config)
    except Exception as e:
        app.logger.error(f"DB connection error: {e}")
        return None

def safe_jsonify(obj):
    # helper to ensure JSON serializable (replace bytes, datetime, bytes objects)
    def convert(o):
        if isinstance(o, bytes):
            return o.decode('utf-8', errors='ignore')
        if isinstance(o, datetime):
            return o.isoformat()
        return o
    return json.loads(json.dumps(obj, default=convert))

# CONCEPTUAL: Visual Forgery Detection Simulation (CNN/GNN Signals)
def get_visual_forgery_signal(img_bytes) -> str:
    """
    Conceptual simulation of calling an external CNN/GNN model
    for visual forgery detection (e.g., splicing, cloning, template overlay).
    """
    # Simulate a low chance of forgery detection for testing
    if random.randint(1, 100) <= 5: # 5% chance of suspected forgery
        return "FORGERY_DETECTED" 
    return "CLEAN" 

# AML Rule Engine (NEW)
def check_aml_blacklist(name: str, id_number: str) -> Dict[str, Any]:
    """
    Conceptual check against an internal or external AML/Sanctions list.
    """
    normalized_name = normalize_name(name)
    
    # Simple simulation: Check for a suspicious pattern in name/ID
    if "SATAN" in normalized_name or id_number.endswith('00013'):
        return {"aml_status": "MATCH", "reason": "Blacklist match (high-risk pattern)."}
    
    return {"aml_status": "CLEAN", "reason": "No match found."}

# Auto Verification Decision Logic (UPDATED to consider face match)
def get_auto_verification_decision(fraud_score_data: Dict[str, Any], aml_result: Dict[str, Any], face_match_result: Dict[str, Any]) -> str:
    """
    Determines the final status based on the aggregated risk score, AML check, and Face Match.
    """
    score = int(fraud_score_data['score'].replace('%', ''))
    
    # Hard rejection rules
    if score >= 80:
        return "REJECTED"
    if aml_result.get('aml_status') == 'MATCH':
        return "REJECTED"
    if face_match_result.get('status') == 'LOW': # Hard reject on low face match
        return "REJECTED"
        
    # Hard verification rules
    if score <= 20 and len(fraud_score_data['factors']) == 0 and face_match_result.get('status') == 'HIGH':
        return "VERIFIED"
        
    # Anything else requires manual review
    return "PENDING"

# Validation utilities (ID format checks - unchanged)
def check_aadhaar_validity(aadhaar_id):
    if not aadhaar_id or aadhaar_id == 'N/A':
        return {"status": "INVALID", "message": "ID missing or not extracted."}
    if re.fullmatch(r'\d{12}', aadhaar_id.replace(" ", "")):
        return {"status": "VALID", "message": "Format matched 12 digits."}
    return {"status": "INVALID", "message": "Format mismatch (expected 12 digits)."}

def check_pan_validity(pan_id):
    if not pan_id or pan_id == 'N/A':
        return {"status": "INVALID", "message": "ID missing or not extracted."}
    if re.fullmatch(r'[A-Z]{5}\d{4}[A-Z]{1}', pan_id):
        return {"status": "VALID", "message": "Format matched AAAAANNNNA."}
    return {"status": "INVALID", "message": "Format mismatch (expected AAAAANNNNA)."}

def check_dl_validity(dl_id):
    if not dl_id or dl_id == 'N/A':
        return {"status": "INVALID", "message": "ID missing or not extracted."}
    clean_id = re.sub(r'[^A-Z0-9]', '', dl_id.upper())
    if re.fullmatch(r'[A-Z]{2}[0-9]{2}[0-9A-Z]{7,}', clean_id):
        return {"status": "VALID", "message": "Format matched Indian DL pattern (AA00XXXX...)."}
    return {"status": "INVALID", "message": "Format mismatch (expected AA00XXXX...)."}

def parse_dob(dob_str):
    """Attempt to parse DOB string (D/M/Y or D-M-Y or YYYY) into a date object or return N/A."""
    if not dob_str or dob_str == 'N/A':
        return None
    
    formats = ['%d/%m/%Y', '%d-%m-%Y', '%Y']
    for fmt in formats:
        try:
            return datetime.strptime(dob_str, fmt).date()
        except ValueError:
            continue
    return None

def check_cross_field_consistency(aadhaar_doc, pan_doc):
    """Performs consistency checks on DOB and Gender across Aadhaar and PAN."""
    consistency_result = {"dob": "N/A", "gender": "N/A"}
    
    if aadhaar_doc and pan_doc:
        # --- DOB Consistency Check ---
        aadhaar_dob_str = aadhaar_doc['extracted_dob']
        pan_dob_str = pan_doc['extracted_dob']
        
        aadhaar_date = parse_dob(aadhaar_dob_str)
        pan_date = parse_dob(pan_dob_str)
        
        if aadhaar_date and pan_date:
            if aadhaar_date == pan_date:
                consistency_result["dob"] = "MATCH"
            else:
                diff = abs((aadhaar_date - pan_date).days)
                if diff < 366: # Less than one year difference
                    consistency_result["dob"] = "CLOSE_MATCH"
                else:
                    consistency_result["dob"] = "MISMATCH"
        else:
            consistency_result["dob"] = "UNPARSEABLE"

        # --- Gender Consistency Check ---
        aadhaar_gender = aadhaar_doc['extracted_gender'].upper()
        pan_gender = pan_doc['extracted_gender'].upper()
        
        if aadhaar_gender in ('M', 'MALE') and pan_gender in ('M', 'MALE'):
            consistency_result["gender"] = "MATCH"
        elif aadhaar_gender in ('F', 'FEMALE') and pan_gender in ('F', 'FEMALE'):
            consistency_result["gender"] = "MATCH"
        elif aadhaar_gender not in ('N/A', '') and pan_gender not in ('N/A', ''):
            consistency_result["gender"] = "MISMATCH"
        else:
            consistency_result["gender"] = "UNPARSEABLE"
            
    return consistency_result

# Fraud Score Calculation (UPDATED for Face Match)
def calculate_fraud_score(aadhaar_validity, pan_validity, dl_validity, match_result, is_duplicate_submission, ocr_confidence=1.0, manipulation_verdict='CLEAN', cross_field_consistency=None, pattern_verdict='CLEAN', visual_forgery_verdict='CLEAN', face_match_result=None):
    risk_points = 0
    risk_factors = []

    # NEW: Risk factor for Face Match
    if face_match_result:
        match_status = face_match_result.get('status')
        match_percent = face_match_result.get('match_percent', 'N/A')
        if match_status == 'LOW':
            risk_points += 50
            risk_factors.append(f"CRITICAL: Face Match Low Confidence ({match_percent}). Identity mismatch highly likely.")
        elif match_status == 'MEDIUM':
            risk_points += 20
            risk_factors.append(f"MED: Face Match Medium Confidence ({match_percent}). Requires manual review.")
        elif match_status == 'N/A':
            # Penalize for not having a live photo available for check
            if "Missing ID or Live photo" in face_match_result.get('error', ''):
                risk_points += 10
                risk_factors.append("LOW: Face match could not be performed (missing live photo/ID image).")


    if is_duplicate_submission:
        risk_points += 40
        risk_factors.append("HIGH: Document ID previously submitted by another user.")
        
    # Risk factor for visual forgery detection (NEW - Highest Risk)
    if visual_forgery_verdict == 'FORGERY_DETECTED':
        risk_points += 55 
        risk_factors.append("CRITICAL: Visual image analysis suggests deep forgery or template cloning.")
        
    # Risk factor for complex pattern detection
    if pattern_verdict == 'SUSPICIOUS':
        risk_points += 35
        risk_factors.append("HIGH: Text pattern analysis suggests templated or generated forgery.")
        
    # Risk factor for simple text manipulation
    if manipulation_verdict == 'SUSPICIOUS':
        risk_points += 25
        risk_factors.append("HIGH: Suspicious text manipulation/inconsistency detected.")
        
    # Risk factors for cross-field consistency
    if cross_field_consistency:
        if cross_field_consistency.get('dob') == 'MISMATCH':
            risk_points += 30
            risk_factors.append("HIGH: Date of Birth inconsistency between Aadhaar and PAN.")
        elif cross_field_consistency.get('dob') == 'CLOSE_MATCH':
            risk_points += 15
            risk_factors.append("MED: Minor Date of Birth inconsistency (suggests OCR error or minor edit).")
            
        if cross_field_consistency.get('gender') == 'MISMATCH':
            risk_points += 30
            risk_factors.append("HIGH: Gender inconsistency between Aadhaar and PAN.")


    if aadhaar_validity and aadhaar_validity['status'] != 'VALID':
        risk_points += 10
        risk_factors.append(f"MED: Aadhaar ID format is invalid ({aadhaar_validity['message']}).")
    if pan_validity and pan_validity['status'] != 'VALID':
        risk_points += 10
        risk_factors.append(f"MED: PAN ID format is invalid ({pan_validity['message']}).")
    if dl_validity and dl_validity['status'] != 'VALID':
        risk_points += 10
        risk_factors.append(f"LOW: DL ID format is invalid ({dl_validity['message']}).")
        
    if match_result:
        try:
            ratio = float(match_result['ratio'].replace('%', ''))
            token_score = float(match_result['token_score'].replace('%', ''))
        except Exception:
            ratio = token_score = 0.0
            
        if ratio < 70 and token_score < 70:
            risk_points += 30
            risk_factors.append("MED: Low name match confidence between Aadhaar and PAN.")
        elif ratio < 80 or token_score < 80:
            risk_points += 15
            risk_factors.append("LOW: Moderate name match inconsistency between documents.")
            
    if ocr_confidence < 0.5:
        risk_points += 20
        risk_factors.append("LOW: Potential document manipulation (low OCR confidence).")
        
    final_score = min(100, risk_points)
    
    if final_score <= 30:
        level, color = "Low Risk", "green"
    elif final_score <= 70:
        level, color = "Medium Risk", "yellow"
    else:
        level, color = "High Risk", "red"
        
    return {'score': f"{final_score}%", 'level': level, 'color': color, 'factors': risk_factors}

# ---------- Routes (API-only) ----------
@app.route('/api/v1/register', methods=['POST', 'OPTIONS'])
def api_register():
    if request.method == 'OPTIONS':
        return '', 200
    data = request.get_json() or {}
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    if not (name and email and password):
        return jsonify({"status":"error","message":"Missing fields"}), 400
    db = get_db()
    if not db:
        return jsonify({"status":"error","message":"Database connection error"}), 500
    cur = db.cursor()
    try:
        # Insert with has_live_photo=0 by default
        cur.execute("INSERT INTO users (name, email, password, has_live_photo) VALUES (%s,%s,%s, 0)", (name, email, password))
        db.commit()
        return jsonify({"status":"success","message":"Registration successful"}), 200
    except mysql.connector.Error as err:
        if 'Duplicate entry' in str(err):
            return jsonify({"status":"error","message":"Email or username already exists"}), 409
        return jsonify({"status":"error","message":str(err)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/v1/user_login', methods=['POST', 'OPTIONS'])
def api_user_login():
    if request.method == 'OPTIONS':
        return '', 200
    data = request.get_json() or {}
    login_id = data.get('username_or_email')
    password = data.get('password')
    if not (login_id and password):
        return jsonify({"success":False,"message":"Provide username/email and password"}), 400
    db = get_db()
    if not db:
        return jsonify({"success":False,"message":"Database connection error"}), 500
    cur = db.cursor(dictionary=True)
    try:
        # Fetch user info including has_live_photo status
        cur.execute("SELECT id, name, email, has_live_photo FROM users WHERE (email=%s OR name=%s) AND password=%s", (login_id, login_id, password))
        user = cur.fetchone()
        if user:
            return jsonify({"success":True,"message":"Login successful","user": user}), 200
        return jsonify({"success":False,"message":"Invalid credentials"}), 401
    except Exception as e:
        return jsonify({"success":False,"message":f"Error: {e}"}), 500
    finally:
        cur.close()
        db.close()

# NEW Route for Live Photo Upload
@app.route('/api/v1/upload_live_photo', methods=['POST', 'OPTIONS'])
def api_upload_live_photo():
    if request.method == 'OPTIONS':
        return '', 200
    user_id = request.form.get('user_id', type=int)
    if 'file' not in request.files or not user_id:
        return jsonify({"status":"error","message":"Missing file or user_id"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"status":"error","message":"Empty filename"}), 400

    db = get_db()
    if not db:
        return jsonify({"status":"error","message":"Database connection error"}), 500
        
    try:
        # 1. Use FaceMatcher to save the photo
        saved_path = face_matcher.save_live_photo(file, user_id)
        
        # 2. Update user status flag in DB
        cur_write = db.cursor()
        cur_write.execute("UPDATE users SET has_live_photo=1 WHERE id=%s", (user_id,))
        db.commit()
        cur_write.close()
        
        return jsonify({"status":"success","message":"Live photo uploaded successfully", "path": saved_path}), 200
    except Exception as e:
        return jsonify({"status":"error","message":f"Live photo upload error: {e}"}), 500
    finally:
        db.close()


@app.route('/api/v1/admin_login', methods=['POST', 'OPTIONS'])
def api_admin_login():
    if request.method == 'OPTIONS':
        return '', 200
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    if username == 'admin' and password == 'admin123':
        return jsonify({"success":True,"message":"Admin login successful"}), 200
    return jsonify({"success":False,"message":"Invalid admin credentials"}), 401

@app.route('/api/v1/get_docs/<int:user_id>', methods=['GET', 'OPTIONS'])
def api_get_docs(user_id):
    if request.method == 'OPTIONS':
        return '', 200
    db = get_db()
    if not db:
        return jsonify({"success":False,"message":"Database connection error"}), 500
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT * FROM documents WHERE user_id=%s ORDER BY uploaded_at DESC", (user_id,))
        docs = cur.fetchall()
        
        for d in docs:
            d['manipulation_verdict'] = 'CLEAN'
            d['pattern_verdict'] = 'CLEAN'
            d['visual_forgery_verdict'] = 'CLEAN' 
            
            if d.get('doc_type') in ('DRIVING_LICENSE', 'AADHAAR') and d.get('metadata'):
                try:
                    parsed = json.loads(d['metadata'])
                    d['metadata_json'] = parsed
                    d['metadata'] = parsed.get('quality_info', d['metadata'])
                    d['manipulation_verdict'] = parsed.get('manipulation_details', {}).get('verdict', 'CLEAN')
                    d['pattern_verdict'] = parsed.get('pattern_details', {}).get('verdict', 'CLEAN')
                    d['visual_forgery_verdict'] = parsed.get('visual_forgery_verdict', 'CLEAN') 
                except Exception:
                    d['metadata_json'] = {}

            # Fallback/string metadata extraction (for PAN or failure case)
            if d.get('doc_type') == 'PAN' or not d.get('metadata_json'):
                match_manip = re.search(r'Manipulation:\s*(\w+)', d.get('metadata', ''))
                d['manipulation_verdict'] = match_manip.group(1) if match_manip else d['manipulation_verdict']
                match_pattern = re.search(r'Pattern:\s*(\w+)', d.get('metadata', ''))
                d['pattern_verdict'] = match_pattern.group(1) if match_pattern else d['pattern_verdict']
                match_visual = re.search(r'Visual Forgery:\s*(\w+)', d.get('metadata', ''))
                d['visual_forgery_verdict'] = match_visual.group(1) if match_visual else d['visual_forgery_verdict']
                
        return jsonify({"success":True,"docs": docs}), 200
    except Exception as e:
        return jsonify({"success":False,"message":str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route('/api/v1/upload_doc', methods=['POST', 'OPTIONS'])
def api_upload_doc():
    if request.method == 'OPTIONS':
        return '', 200
    user_id = request.form.get('user_id', type=int)
    user_name = request.form.get('user_name')
    doc_type = request.form.get('doc_type')
    if 'file' not in request.files or not user_id or not doc_type:
        return jsonify({"status":"error","message":"Missing file, user_id or doc_type"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"status":"error","message":"Empty filename"}), 400

    file.seek(0)
    img_bytes = file.read()
    file.seek(0)

    # 1. Image quality check
    quality = check_image_quality(img_bytes)
    if quality.get('verdict') == 'BAD':
        return jsonify({"status":"error","message":"Poor image quality", "details": quality}), 400

    # 2. Perform OCR
    ocr_text = perform_ocr(img_bytes)
    
    # 3. NLP Checks
    manipulation_check = check_text_manipulation(ocr_text)
    manipulation_verdict = manipulation_check['verdict']
    pattern_check = check_complex_patterns(ocr_text)
    pattern_verdict = pattern_check['verdict']
    
    # 4. Visual Forgery Check (CNN/GNN Simulation)
    visual_forgery_verdict = get_visual_forgery_signal(img_bytes)

    db = get_db()
    if not db:
        return jsonify({"status":"error","message":"Database connection error"}), 500
    cur_read = db.cursor(dictionary=True)
    doc_type_to_save = None
    extracted = {}
    extra_metadata = {}

    try:
        # Check for Aadhaar document to get name for PAN linking
        aadhaar_name = None
        if doc_type == 'PAN':
            cur_read.execute("""
                SELECT extracted_name FROM documents
                WHERE user_id=%s AND doc_type='AADHAAR' AND status != 'REJECTED'
                ORDER BY uploaded_at DESC LIMIT 1
            """, (user_id,))
            r = cur_read.fetchone()
            aadhaar_name = r['extracted_name'] if r and r.get('extracted_name') else None
        
        # Run extraction based on doc_type
        if doc_type == 'PAN':
            doc_type_to_save = 'PAN'
            extracted = extract_pan_with_link(ocr_text, aadhaar_name=aadhaar_name, user_name_hint=user_name)
            
        elif doc_type == 'AADHAAR':
            doc_type_to_save = 'AADHAAR'
            extracted = extract_aadhaar(ocr_text, user_name_hint=user_name)
            extracted['address'] = normalize_address(extracted.get('address','N/A'))
            
        elif doc_type == 'DRIVING_LICENSE':
            doc_type_to_save = 'DRIVING_LICENSE'
            extracted = extract_driving_license(ocr_text, user_name_hint=user_name)
            extracted['address'] = normalize_address(extracted.get('address','N/A'))
            
            extra_metadata = {
                'father_name': extracted.get('father_name','N/A'),
                'blood_group': extracted.get('blood_group','N/A'),
                'issue_date': extracted.get('issue_date','N/A'),
                'valid_till': extracted.get('valid_till','N/A'),
                'address': extracted.get('address','N/A'),
                'normalized_address': extracted['address']
            }
        else:
            return jsonify({"status":"error","message":"Invalid doc_type"}), 400

        # Duplicate check (if ID is extracted)
        ext_id = extracted.get('id')
        if ext_id and ext_id != 'N/A':
            cur_read.execute("SELECT user_id FROM documents WHERE extracted_id=%s AND doc_type=%s AND user_id!=%s LIMIT 1",
                             (ext_id, doc_type_to_save, user_id))
            dup = cur_read.fetchone()
            if dup:
                return jsonify({"status":"error","message":f"This {doc_type_to_save} ID already uploaded by another user"}), 409

    except Exception as e:
        return jsonify({"status":"error","message":f"Extraction/DB error: {e}"}), 500
    finally:
        cur_read.close()

    # Save file physically
    safe_name = os.path.basename(file.filename)
    filename = f"{user_id}_{doc_type_to_save}_{safe_name}"
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    try:
        file.save(path)
    except Exception as e:
        return jsonify({"status":"error","message":f"File save error: {e}"}), 500

    # Insert record
    cur_write = db.cursor()
    try:
        # Store all primary verdicts in quality_info string for quick review/indexing
        quality_info = (
            f"Verdict: {quality.get('verdict','N/A')} | "
            f"Sharpness: {quality.get('blur_score',0.0):.2f} | "
            f"Low Res: {quality.get('is_low_res', False)} | "
            f"Manipulation: {manipulation_verdict} | "
            f"Pattern: {pattern_verdict} | "
            f"Visual Forgery: {visual_forgery_verdict}"
        )
        
        # Store detailed metadata as JSON for DL and Aadhaar (clean verdict storage)
        if doc_type_to_save in ('DRIVING_LICENSE', 'AADHAAR'):
            full_meta = extra_metadata if doc_type_to_save == 'DRIVING_LICENSE' else {}
            full_meta['quality_info'] = quality_info
            full_meta['manipulation_details'] = manipulation_check 
            full_meta['pattern_details'] = pattern_check
            full_meta['visual_forgery_verdict'] = visual_forgery_verdict
            if doc_type_to_save == 'AADHAAR':
                 full_meta['normalized_address'] = extracted['address']
            metadata_to_save = json.dumps(full_meta)
        else:
            # For PAN, use the simpler string format
            metadata_to_save = quality_info

        cur_write.execute("""
            INSERT INTO documents (user_id, doc_type, filename, ocr_text,
                extracted_name, extracted_dob, extracted_gender, extracted_id, status, metadata)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'PENDING',%s)
        """, (
            user_id, doc_type_to_save, filename, ocr_text,
            extracted.get('name','N/A'), extracted.get('dob','N/A'),
            extracted.get('gender','N/A'), extracted.get('id','N/A'),
            metadata_to_save
        ))
        db.commit()
        return jsonify({"status":"success","message":"Document uploaded and queued for review"}), 200
    except Exception as e:
        return jsonify({"status":"error","message":f"DB write error: {e}"}), 500
    finally:
        cur_write.close()
        db.close()

# Automatic Verification Pipeline (UPDATED for Face Match)
@app.route('/api/v1/verify_identity/<int:user_id>', methods=['POST', 'OPTIONS'])
def api_verify_identity(user_id):
    if request.method == 'OPTIONS':
        return '', 200
        
    db = get_db()
    if not db:
        return jsonify({"status":"error","message":"DB error"}), 500
        
    cur = db.cursor(dictionary=True)
    cur_write = db.cursor()
    
    try:
        # 1. Fetch User Info
        cur.execute("SELECT id, name, email, has_live_photo FROM users WHERE id=%s", (user_id,))
        user_info = cur.fetchone()
        if not user_info:
            return jsonify({"status":"error","message":"User not found"}), 404
        user_name = user_info['name']
        has_live_photo = user_info['has_live_photo']
        
        # 2. Fetch Latest Documents (only non-rejected)
        cur.execute("SELECT * FROM documents WHERE user_id=%s AND status != 'REJECTED' ORDER BY uploaded_at DESC", (user_id,))
        docs = cur.fetchall()
        
        # Get latest Aadhaar and PAN (Aadhaar typically has best photo)
        aadhaar = next((x for x in docs if x['doc_type']=='AADHAAR'), None)
        pan = next((x for x in docs if x['doc_type']=='PAN'), None)
        dl = next((x for x in docs if x['doc_type']=='DRIVING_LICENSE'), None)

        if not (aadhaar and pan):
            return jsonify({"status": "pending", "message": "Verification requires both Aadhaar and PAN."}), 200
        
        # 3. Face Matching Check
        face_match_result = {"status": "N/A", "match_percent": "0%", "error": "Live photo missing."}
        if has_live_photo and aadhaar:
            AADHAAR_DOC_PATH = os.path.join(app.config['UPLOAD_FOLDER'], aadhaar['filename'])
            # Rely on FaceMatcher's default filename convention
            LIVE_PHOTO_PATH = os.path.join(face_matcher.live_folder, f"user_{user_id}_live.jpg") 

            if os.path.exists(AADHAAR_DOC_PATH) and os.path.exists(LIVE_PHOTO_PATH):
                face_match_result = face_matcher.match_faces(AADHAAR_DOC_PATH, LIVE_PHOTO_PATH)
            else:
                face_match_result = {"status": "N/A", "match_percent": "0%", "error": "Missing ID or Live photo file."}

        # 4. Validation & Scoring Checks
        aadhaar_validity = check_aadhaar_validity(aadhaar['extracted_id'])
        pan_validity = check_pan_validity(pan['extracted_id'])
        dl_validity = check_dl_validity(dl['extracted_id']) if dl else None
        
        cross_field_consistency = check_cross_field_consistency(aadhaar, pan)
        match_result = compare_names(aadhaar['extracted_name'], pan['extracted_name'])

        # Aggregate verdicts from key docs
        overall_manipulation = 'SUSPICIOUS' if any(re.search(r'Manipulation:\s*SUSPICIOUS', d.get('metadata', '')) for d in [aadhaar, pan]) else 'CLEAN'
        overall_pattern = 'SUSPICIOUS' if any(re.search(r'Pattern:\s*SUSPICIOUS', d.get('metadata', '')) for d in [aadhaar, pan]) else 'CLEAN'
        overall_visual_forgery = 'FORGERY_DETECTED' if any(re.search(r'Visual Forgery:\s*FORGERY_DETECTED', d.get('metadata', '')) for d in [aadhaar, pan]) else 'CLEAN'

        fraud_score = calculate_fraud_score(
            aadhaar_validity, pan_validity, dl_validity, 
            match_result, False, 
            manipulation_verdict=overall_manipulation,
            cross_field_consistency=cross_field_consistency,
            pattern_verdict=overall_pattern,
            visual_forgery_verdict=overall_visual_forgery,
            face_match_result=face_match_result # NEW ARGUMENT
        )
        
        # 5. AML Check
        aml_result = check_aml_blacklist(user_name, aadhaar['extracted_id'])

        # 6. Auto Decision
        new_status = get_auto_verification_decision(fraud_score, aml_result, face_match_result)
        
        # 7. Update Status (Batch update all key docs)
        cur_write.execute("UPDATE documents SET status=%s WHERE user_id=%s AND doc_type IN ('AADHAAR', 'PAN')", (new_status, user_id))
        
        # 8. Store final fraud/AML metadata (Conceptual: Storing results in the user record or a dedicated verification table)
        final_meta = {
            "fraud_score": fraud_score,
            "aml_result": aml_result,
            "face_match_result": face_match_result, # NEW
            "final_status": new_status,
            "updated_at": datetime.now().isoformat()
        }
        # Update a conceptual verification status table (or user table)
        cur_write.execute("UPDATE users SET verification_status=%s, verification_metadata=%s WHERE id=%s", (new_status, json.dumps(final_meta), user_id))

        db.commit()
        
        return jsonify({
            "status": new_status.lower(),
            "message": f"Identity verification complete. Final status: {new_status}.",
            "details": final_meta
        }), 200

    except Exception as e:
        db.rollback()
        app.logger.error(f"Verification Pipeline Error for user {user_id}: {e}")
        return jsonify({"status":"error","message":f"Verification failed: {e}"}), 500
    finally:
        cur.close()
        cur_write.close()
        db.close()


# Fraud Alerts API (unchanged)
@app.route('/api/admin/alerts', methods=['GET', 'OPTIONS'])
def api_admin_alerts():
    if request.method == 'OPTIONS':
        return '', 200
    db = get_db()
    if not db:
        return jsonify({"success":False,"message":"Database connection error"}), 500
    cur = db.cursor(dictionary=True)
    try:
        # Fetching documents that are REJECTED or PENDING and have high risk indicators 
        cur.execute("""
            SELECT u.id as user_id, u.name, d.id as doc_id, d.doc_type, d.status, d.uploaded_at, d.metadata
            FROM documents d
            JOIN users u ON d.user_id = u.id
            WHERE d.status IN ('REJECTED', 'PENDING')
              AND (d.metadata LIKE '%FORGERY_DETECTED%' 
                   OR d.metadata LIKE '%Manipulation: SUSPICIOUS%' 
                   OR d.metadata LIKE '%Pattern: SUSPICIOUS%')
            ORDER BY d.uploaded_at DESC
        """)
        alerts = cur.fetchall()
        return jsonify({"success":True,"alerts": alerts}), 200
    except Exception as e:
        return jsonify({"success":False,"message":str(e)}), 500
    finally:
        cur.close()
        db.close()


# Admin dashboard (list users + doc counts) - updated to include live photo status
@app.route('/api/admin/dashboard', methods=['GET','OPTIONS'])
@app.route('/api/v1/admin/dashboard', methods=['GET','OPTIONS'])
def api_admin_dashboard():
    if request.method == 'OPTIONS':
        return '', 200
    db = get_db()
    if not db:
        return jsonify({"success":False,"message":"Database connection error"}), 500
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("""
            SELECT u.id as user_id, u.name as user_name, u.email, u.verification_status, u.has_live_photo,
                SUM(CASE WHEN d.doc_type = 'AADHAAR' THEN 1 ELSE 0 END) as aadhaar_count,
                SUM(CASE WHEN d.doc_type = 'PAN' THEN 1 ELSE 0 END) as pan_count,
                SUM(CASE WHEN d.doc_type = 'DRIVING_LICENSE' THEN 1 ELSE 0 END) as dl_count,
                SUM(CASE WHEN d.status = 'PENDING' THEN 1 ELSE 0 END) as pending_count,
                MAX(d.uploaded_at) as last_upload_at
            FROM users u
            LEFT JOIN documents d ON u.id = d.user_id
            GROUP BY u.id, u.name, u.email, u.verification_status, u.has_live_photo
            ORDER BY u.id DESC
        """)
        rows = cur.fetchall()
        return jsonify({"success":True,"users": rows}), 200
    except Exception as e:
        return jsonify({"success":False,"message":str(e)}), 500
    finally:
        cur.close()
        db.close()

# Admin review endpoint (UPDATED for Face Match)
@app.route('/api/admin/review/<int:user_id>', methods=['GET','POST','OPTIONS'])
@app.route('/api/v1/admin/review/<int:user_id>', methods=['GET','POST','OPTIONS'])
def api_admin_review(user_id):
    if request.method == 'OPTIONS':
        return '', 200
    db = get_db()
    if not db:
        return jsonify({"status":"error","message":"DB error"}), 500
    cur = db.cursor(dictionary=True)
    try:
        # POST logic for name correction/re-verification (unchanged)
        action = None
        corrected_name = None
        pan_doc_id = None
        if request.method == 'POST':
            data = request.get_json() or {}
            action = data.get('action')
            corrected_name = (data.get('corrected_name') or '').strip().upper()
            pan_doc_id = data.get('pan_doc_id')
            if action == 'save_and_verify':
                if not (pan_doc_id and corrected_name):
                    return jsonify({"status":"error","message":"Missing pan_doc_id or corrected_name"}), 400
                cur_write = db.cursor()
                cur_write.execute("UPDATE documents SET extracted_name=%s, status='PENDING' WHERE id=%s",
                                 (corrected_name, pan_doc_id))
                db.commit()
                cur_write.close()
            elif action and action != 'test_match':
                return jsonify({"status":"error","message":"Invalid action"}), 400

        # Fetch user info and docs
        cur.execute("SELECT id, name, email, has_live_photo FROM users WHERE id=%s", (user_id,))
        user_info = cur.fetchone()
        if not user_info:
            return jsonify({"status":"error","message":"User not found"}), 404
        has_live_photo = user_info['has_live_photo']
        
        cur.execute("SELECT * FROM documents WHERE user_id=%s ORDER BY doc_type DESC, uploaded_at DESC", (user_id,))
        docs = cur.fetchall()
        
        # Parse metadata and extract verdicts
        for d in docs:
            d['metadata_json'] = {}
            d['manipulation_verdict'] = 'CLEAN'
            d['pattern_verdict'] = 'CLEAN'
            d['visual_forgery_verdict'] = 'CLEAN'
            
            if d.get('doc_type') in ('DRIVING_LICENSE', 'AADHAAR') and d.get('metadata'):
                try:
                    pj = json.loads(d['metadata'])
                    d['metadata_json'] = pj
                    d['metadata'] = pj.get('quality_info', d['metadata'])
                    d['manipulation_verdict'] = pj.get('manipulation_details', {}).get('verdict', 'CLEAN')
                    d['pattern_verdict'] = pj.get('pattern_details', {}).get('verdict', 'CLEAN')
                    d['visual_forgery_verdict'] = pj.get('visual_forgery_verdict', 'CLEAN')
                except Exception:
                    pass
                
            # Fallback/string metadata extraction (for PAN or failure case)
            if d.get('doc_type') == 'PAN' or not d.get('metadata_json'):
                match_manip = re.search(r'Manipulation:\s*(\w+)', d.get('metadata', ''))
                d['manipulation_verdict'] = match_manip.group(1) if match_manip else d['manipulation_verdict']
                match_pattern = re.search(r'Pattern:\s*(\w+)', d.get('metadata', ''))
                d['pattern_verdict'] = match_pattern.group(1) if match_pattern else d['pattern_verdict']
                match_visual = re.search(r'Visual Forgery:\s*(\w+)', d.get('metadata', ''))
                d['visual_forgery_verdict'] = match_visual.group(1) if match_visual else d['visual_forgery_verdict']

        # pick recent non-rejected Aadhaar/PAN/DL
        aadhaar = next((x for x in docs if x['doc_type']=='AADHAAR' and x['status']!='REJECTED'), None) or next((x for x in docs if x['doc_type']=='AADHAAR'), None)
        pan = next((x for x in docs if x['doc_type']=='PAN' and x['status']!='REJECTED'), None) or next((x for x in docs if x['doc_type']=='PAN'), None)
        dl = next((x for x in docs if x['doc_type']=='DRIVING_LICENSE' and x['status']!='REJECTED'), None) or next((x for x in docs if x['doc_type']=='DRIVING_LICENSE'), None)

        pan_name_for_match = pan['extracted_name'] if pan else 'N/A'
        if request.method == 'POST' and action in ('test_match','save_and_verify') and corrected_name:
            pan_name_for_match = corrected_name
            if action == 'save_and_verify' and pan:
                pan['extracted_name'] = corrected_name

        aadhaar_validity = check_aadhaar_validity(aadhaar['extracted_id']) if aadhaar else None
        pan_validity = check_pan_validity(pan['extracted_id']) if pan else None
        dl_validity = check_dl_validity(dl['extracted_id']) if dl else None
        
        # --- Initialize variables before conditional use ---
        match_result = None
        fraud_score = None
        cross_field_consistency = None
        overall_status = "INCOMPLETE" 
        face_match_result = {"status": "N/A", "match_percent": "0%", "error": "Live photo missing."} # Initialize
        # --------------------------------------------------------
        
        # Face Matching Check (For Review Screen)
        if has_live_photo and aadhaar:
            AADHAAR_DOC_PATH = os.path.join(app.config['UPLOAD_FOLDER'], aadhaar['filename'])
            LIVE_PHOTO_PATH = os.path.join(face_matcher.live_folder, f"user_{user_id}_live.jpg") 

            if os.path.exists(AADHAAR_DOC_PATH) and os.path.exists(LIVE_PHOTO_PATH):
                face_match_result = face_matcher.match_faces(AADHAAR_DOC_PATH, LIVE_PHOTO_PATH)
            else:
                face_match_result = {"status": "N/A", "match_percent": "0%", "error": "Missing ID or Live photo file."}


        if aadhaar and pan:
            # Determine overall status based on current document flags for the review screen
            if aadhaar['status'] == 'PENDING' or pan['status'] == 'PENDING':
                overall_status = "PENDING REVIEW"
            elif aadhaar['status'] == 'REJECTED' or pan['status'] == 'REJECTED':
                overall_status = "REJECTED"
            elif aadhaar['status'] == 'VERIFIED' and pan['status'] == 'VERIFIED':
                overall_status = "FULLY VERIFIED"
            else:
                overall_status = "PENDING REVIEW" # Default for safety

            cross_field_consistency = check_cross_field_consistency(aadhaar, pan)
            match_result = compare_names(aadhaar['extracted_name'], pan_name_for_match)
            
            # Determine overall fraud verdicts
            overall_manipulation = 'SUSPICIOUS' if any(d.get('manipulation_verdict') == 'SUSPICIOUS' for d in [aadhaar, pan, dl] if d) else 'CLEAN'
            overall_pattern = 'SUSPICIOUS' if any(d.get('pattern_verdict') == 'SUSPICIOUS' for d in [aadhaar, pan, dl] if d) else 'CLEAN'
            overall_visual_forgery = 'FORGERY_DETECTED' if any(d.get('visual_forgery_verdict') == 'FORGERY_DETECTED' for d in [aadhaar, pan, dl] if d) else 'CLEAN'
            
            fraud_score = calculate_fraud_score(
                aadhaar_validity, pan_validity, dl_validity, 
                match_result, False, 
                manipulation_verdict=overall_manipulation,
                cross_field_consistency=cross_field_consistency,
                pattern_verdict=overall_pattern,
                visual_forgery_verdict=overall_visual_forgery,
                face_match_result=face_match_result # NEW ARGUMENT
            )
            
            if fraud_score['level']=='High Risk' and match_result:
                match_result['verdict'] = f"HIGH RISK (Score: {fraud_score['score']})"
                match_result['color'] = fraud_score['color']
            elif match_result and match_result.get('verdict')=='Strong Match' and aadhaar_validity and pan_validity and aadhaar_validity['status']=='VALID' and pan_validity['status']=='VALID':
                match_result['verdict'] = "STRONG MATCH (Automated Green Flag)"
                match_result['color'] = "green"

        resp = {
            "status":"success",
            "user_info": user_info,
            "docs": docs,
            "aadhaar_doc": aadhaar,
            "pan_doc": pan,
            "dl_doc": dl,
            "aadhaar_validity": aadhaar_validity,
            "pan_validity": pan_validity,
            "dl_validity": dl_validity,
            "match_result": match_result,
            "fraud_score": fraud_score,
            "cross_field_consistency": cross_field_consistency, 
            "face_match_result": face_match_result, # NEW
            "overall_status": overall_status 
        }
        if request.method == 'POST' and action == 'save_and_verify':
            resp['message'] = f"PAN name updated to {corrected_name} and re-verified"
        return jsonify(resp), 200
    except Exception as e:
        app.logger.error(f"Review API Error for user {user_id}: {e}")
        return jsonify({"status":"error","message":str(e)}), 500
    finally:
        cur.close()
        db.close()

# Admin actions (verify/reject/delete) - provided for completeness
def _api_update_doc_status(doc_id, status):
    db = get_db()
    if not db:
        return {"status":"error","message":"DB connection error"}, 500
    cur = db.cursor()
    try:
        cur.execute("UPDATE documents SET status=%s WHERE id=%s", (status, doc_id))
        db.commit()
        return {"status":"success","message":f"Document {doc_id} set to {status}"}, 200
    except Exception as e:
        return {"status":"error","message":str(e)}, 500
    finally:
        cur.close()
        db.close()

@app.route('/api/admin/verify_doc/<int:doc_id>', methods=['POST','OPTIONS'])
@app.route('/api/v1/admin/verify_doc/<int:doc_id>', methods=['POST','OPTIONS'])
def api_verify_doc(doc_id):
    if request.method == 'OPTIONS': return '', 200
    res, code = _api_update_doc_status(doc_id, 'VERIFIED')
    return jsonify(res), code

@app.route('/api/admin/reject_doc/<int:doc_id>', methods=['POST','OPTIONS'])
@app.route('/api/v1/admin/reject_doc/<int:doc_id>', methods=['POST','OPTIONS'])
def api_reject_doc(doc_id):
    if request.method == 'OPTIONS': return '', 200
    res, code = _api_update_doc_status(doc_id, 'REJECTED')
    return jsonify(res), code

@app.route('/api/admin/delete_doc/<int:doc_id>', methods=['DELETE','OPTIONS'])
@app.route('/api/v1/admin/delete_doc/<int:doc_id>', methods=['DELETE','OPTIONS'])
def api_delete_doc(doc_id):
    if request.method == 'OPTIONS': return '', 200
    db = get_db()
    if not db:
        return jsonify({"status":"error","message":"DB error"}), 500
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT filename FROM documents WHERE id=%s", (doc_id,))
        doc = cur.fetchone()
        if not doc:
            return jsonify({"status":"error","message":"Document not found"}), 404
        filename = doc['filename']
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        cur_del = db.cursor()
        cur_del.execute("DELETE FROM documents WHERE id=%s", (doc_id,))
        db.commit()
        cur_del.close()
        return jsonify({"status":"success","message":"Document deleted"}), 200
    except Exception as e:
        return jsonify({"status":"error","message":str(e)}), 500
    finally:
        cur.close()
        db.close()

# Small utility: serve uploaded file (optional, used by frontend if needed)
@app.route('/uploads/<path:filename>', methods=['GET'])
def serve_upload(filename):
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(path):
        return send_file(path)
    return jsonify({"status":"error","message":"File not found"}), 404

# Default health check
@app.route('/api/health', methods=['GET'])
def api_health():
    return jsonify({"status":"ok","service":"smartkyc-backend"}), 200

# ---------- Runner ----------
if __name__ == '__main__':
    # run debug for dev; change host/port as needed
    app.run(debug=True, host='0.0.0.0', port=5000)