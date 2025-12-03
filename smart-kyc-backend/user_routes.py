import os
import json
import requests
from flask import Blueprint, request, jsonify, current_app
from datetime import datetime
import mysql.connector 

# Local module imports
from config import UPLOAD_FOLDER, FACE_MATCHER_SERVICE, LIVE_PHOTO_FOLDER
from db import get_db
from helpers import safe_jsonify, get_visual_forgery_signal, check_aml_blacklist, extract_verdict_from_metadata
from scoring_logic import check_aadhaar_validity, check_pan_validity, check_dl_validity, check_cross_field_consistency, calculate_fraud_score, get_auto_verification_decision

# OCR / name matching imports
from ocr_utils import perform_ocr, extract_aadhaar, extract_aadhaar_back, extract_pan_with_link, extract_driving_license, extract_utility_bill, check_image_quality
from name_match import compare_names

# NLP / text understanding imports
from smart_text_utils import check_text_manipulation, normalize_name, normalize_address, check_complex_patterns 

# --- NEW: Device Fingerprinting & Fraud Utils ---
from device_fingerprint import get_device_info
from fraud_utils import check_multiple_uploads_same_device, check_multiple_devices_same_user


user_bp = Blueprint('user_routes', __name__, url_prefix='/api/v1')

# --- HELPER: AUDIT LOGGER ---
def log_audit_event(cursor, actor_type, actor_id, action, details, user_id=None, doc_id=None):
    """Helper to insert logs into the audit_logs table."""
    try:
        cursor.execute("""
            INSERT INTO audit_logs (actor_type, actor_id, action, details, related_user_id, related_doc_id)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (actor_type, actor_id, action, details, user_id, doc_id))
    except Exception as e:
        print(f"Failed to log audit event: {e}")

# --- USER ROUTES ---

@user_bp.route('/register', methods=['POST'])
def api_register():
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
        # Insert with has_live_photo=0, verification_status='NEW' by default
        cur.execute("INSERT INTO users (name, email, password, has_live_photo, verification_status) VALUES (%s,%s,%s, 0, 'NEW')", (name, email, password))
        new_user_id = cur.lastrowid
        
        # Log Registration
        log_audit_event(cur, 'USER', new_user_id, 'USER_REGISTERED', f"Email: {email}", new_user_id, None)
        
        db.commit()
        return jsonify({"status":"success","message":"Registration successful"}), 200
    except mysql.connector.Error as err:
        if 'Duplicate entry' in str(err):
            return jsonify({"status":"error","message":"Email or username already exists"}), 409
        current_app.logger.error(f"Registration error: {err}")
        return jsonify({"status":"error","message":str(err)}), 500
    finally:
        cur.close()
        db.close()

@user_bp.route('/user_login', methods=['POST'])
def api_user_login():
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
        # Fetch user info including live photo status and verification status
        cur.execute("SELECT id, name, email, has_live_photo, verification_status FROM users WHERE (email=%s OR name=%s) AND password=%s", (login_id, login_id, password))
        user = cur.fetchone()
        if user:
                # Log Login (Optional, might be noisy)
                # log_audit_event(cur, 'USER', user['id'], 'LOGIN', 'User logged in', user['id'], None)
                # db.commit() # Need to commit if we log here
                
                return jsonify({
                "success": True,
                "message": "Login successful",
                "role": "user",
                "user": user
            }), 200
        return jsonify({"success":False,"message":"Invalid credentials"}), 401
    except Exception as e:
        current_app.logger.error(f"Login error: {e}")
        return jsonify({"success":False,"message":f"Error: {e}"}), 500
    finally:
        cur.close()
        db.close()

@user_bp.route('/upload_live_photo', methods=['POST'])
def api_upload_live_photo():
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
        saved_path = FACE_MATCHER_SERVICE.save_live_photo(file, user_id)
        
        # 2. Update user status flag in DB
        cur_write = db.cursor()
        cur_write.execute("UPDATE users SET has_live_photo=1 WHERE id=%s", (user_id,))
        
        # Log Action
        log_audit_event(cur_write, 'USER', user_id, 'LIVE_PHOTO_UPLOADED', "User uploaded selfie for liveness check", user_id, None)
        
        db.commit()
        cur_write.close()
        
        return jsonify({"status":"success","message":"Live photo uploaded successfully", "path": saved_path}), 200
    except Exception as e:
        current_app.logger.error(f"Live photo upload error: {e}")
        return jsonify({"status":"error","message":f"Live photo upload error: {e}"}), 500
    finally:
        db.close()

@user_bp.route('/get_docs/<int:user_id>', methods=['GET'])
def api_get_docs(user_id):
    db = get_db()
    if not db:
        return jsonify({"success":False,"message":"Database connection error"}), 500
    
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT * FROM documents WHERE user_id=%s ORDER BY uploaded_at DESC", (user_id,))
        docs = cur.fetchall()
        
        # Extract verdicts from metadata for display
        for d in docs:
            d['manipulation_verdict'] = extract_verdict_from_metadata(d.get('metadata', ''), 'Manipulation')
            d['pattern_verdict'] = extract_verdict_from_metadata(d.get('metadata', ''), 'Pattern')
            d['visual_forgery_verdict'] = extract_verdict_from_metadata(d.get('metadata', ''), 'Visual Forgery')
            
            # Optionally parse full JSON metadata if available
            if d.get('doc_type') in ('DRIVING_LICENSE', 'AADHAAR', 'UTILITY_BILL', 'AADHAAR_BACK') and d.get('metadata'):
                 try:
                      parsed = json.loads(d['metadata'])
                      d['metadata_json'] = parsed
                 except Exception:
                      d['metadata_json'] = {}
            else:
                 d['metadata_json'] = {}
                
        return jsonify({"success":True,"docs": docs}), 200
    except Exception as e:
        current_app.logger.error(f"Get docs error: {e}")
        return jsonify({"success":False,"message":str(e)}), 500
    finally:
        cur.close()
        db.close()

@user_bp.route('/upload_doc', methods=['POST'])
def api_upload_doc():
    user_id = request.form.get('user_id', type=int)
    user_name = request.form.get('user_name')
    doc_type = request.form.get('doc_type')
    
    if 'file' not in request.files or not user_id or not doc_type:
        return jsonify({"status":"error","message":"Missing file, user_id or doc_type"}), 400

    # --- NEW: DEVICE FINGERPRINTING ---
    # We capture device info early to log the attempt
    device_info = None
    try:
        device_info = get_device_info()
        db_log = get_db()
        if db_log:
            cur_log = db_log.cursor()
            cur_log.execute("""
                INSERT INTO device_logs (user_id, device_hash, browser, platform, ip, user_agent, timestamp)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                user_id,
                device_info["device_hash"],
                device_info["browser"],
                device_info["platform"],
                device_info["ip"],
                device_info["user_agent"],
                device_info["timestamp"]
            ))
            db_log.commit()
            cur_log.close()
    except Exception as dev_e:
        current_app.logger.error(f"Device fingerprint logging failed: {dev_e}")
        # We don't block upload if logging fails, but we note it
    # ----------------------------------

    file = request.files['file']
    if file.filename == '':
        return jsonify({"status":"error","message":"Empty filename"}), 400

    file.seek(0)
    img_bytes = file.read()
    file.seek(0) # Reset file pointer for saving later

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
    
    # Flag: Track if we need to delete a previously REJECTED document to allow re-upload
    doc_id_to_delete = None

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
        
        # --- NEW: Handle Aadhaar Back ---
        elif doc_type == 'AADHAAR_BACK':
            doc_type_to_save = 'AADHAAR_BACK'
            extracted = extract_aadhaar_back(ocr_text)
            extracted['name'] = 'N/A' # Back side doesn't have name usually
            extracted['id'] = 'N/A'   # ID might be there but we don't rely on it for uniqueness check
            
            # We save the address in extra_metadata for the JSON field
            extra_metadata = {
                'address': extracted.get('address', 'N/A'),
                'pincode': extracted.get('pincode', 'N/A'),
                'normalized_address': extracted.get('address', 'N/A')
            }
        # -------------------------------
            
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
            
        elif doc_type == 'UTILITY_BILL':
            doc_type_to_save = 'UTILITY_BILL'
            extracted = extract_utility_bill(ocr_text, user_name_hint=user_name)
            extracted['address'] = normalize_address(extracted.get('address', 'N/A'))

            extra_metadata = {
                'provider': extracted.get('provider', 'N/A'),
                'bill_date': extracted.get('bill_date', 'N/A'),
                'amount': extracted.get('amount', 'N/A'),
                'address': extracted.get('address', 'N/A'),
                'normalized_address': extracted['address']
            }
            
        else:
            return jsonify({"status":"error","message":"Invalid doc_type"}), 400

        # --- SMART DUPLICATE CHECK & REJECTION HANDLING ---
        ext_id = extracted.get('id')
        if ext_id and ext_id != 'N/A' and doc_type_to_save != 'AADHAAR_BACK': # Skip dup check for back side
            # Check if this ID exists anywhere in the system
            cur_read.execute("SELECT id, user_id, status FROM documents WHERE extracted_id=%s AND doc_type=%s",
                             (ext_id, doc_type_to_save))
            existing_entries = cur_read.fetchall()
            
            for entry in existing_entries:
                if entry['user_id'] != user_id:
                    # If ID belongs to another user -> Block strict
                    return jsonify({"status":"error","message":f"This {doc_type_to_save} ID is already linked to another account."}), 409
                else:
                    # If ID belongs to THIS user
                    if entry['status'] == 'REJECTED':
                        # If it was rejected, mark it for deletion so we can insert the fresh copy
                        doc_id_to_delete = entry['id']
                        current_app.logger.info(f"Found REJECTED duplicate (ID: {doc_id_to_delete}). Will replace with new upload.")
                    elif entry['status'] in ['PENDING', 'APPROVED']:
                        # If it is pending/approved, don't allow duplicate
                        return jsonify({"status":"error","message":f"You have already uploaded this document (Status: {entry['status']})"}), 409
        # --------------------------------------------------

    except Exception as e:
        current_app.logger.error(f"Extraction/DB read error during upload: {e}")
        return jsonify({"status":"error","message":f"Extraction/DB error: {e}"}), 500
    finally:
        cur_read.close()

    # Save file physically
    safe_name = os.path.basename(file.filename)
    filename = f"{user_id}_{doc_type_to_save}_{safe_name}"
    path = os.path.join(UPLOAD_FOLDER, filename)
    try:
        # File object pointer is reset (file.seek(0) earlier)
        file.save(path)
    except Exception as e:
        current_app.logger.error(f"File save error: {e}")
        return jsonify({"status":"error","message":f"File save error: {e}"}), 500

    # Insert record (WITH DELETION OF OLD REJECTED RECORD IF NEEDED)
    cur_write = db.cursor()
    try:
        # 1. Delete the old rejected record if identified (resolves Unique Constraint error)
        if doc_id_to_delete:
            cur_write.execute("DELETE FROM documents WHERE id=%s", (doc_id_to_delete,))
            current_app.logger.info(f"Deleted old rejected document {doc_id_to_delete} to allow retry.")

        # Store all primary verdicts in quality_info string for quick review/indexing
        quality_info = (
            f"Verdict: {quality.get('verdict','N/A')} | "
            f"Sharpness: {quality.get('blur_score',0.0):.2f} | "
            f"Low Res: {quality.get('is_low_res', False)} | "
            f"Manipulation: {manipulation_verdict} | "
            f"Pattern: {pattern_verdict} | "
            f"Visual Forgery: {visual_forgery_verdict}"
        )
        
        # Store detailed metadata as JSON for DL, Aadhaar, Utility Bill AND Aadhaar Back
        if doc_type_to_save in ('DRIVING_LICENSE', 'AADHAAR', 'UTILITY_BILL', 'AADHAAR_BACK'):
            # extra_metadata is already populated for these types above
            full_meta = extra_metadata 
            full_meta['quality_info'] = quality_info
            full_meta['manipulation_details'] = manipulation_check 
            full_meta['pattern_details'] = pattern_check
            full_meta['visual_forgery_verdict'] = visual_forgery_verdict
            if doc_type_to_save == 'AADHAAR':
                 full_meta['normalized_address'] = extracted['address']
            
            # --- ADD DEVICE INFO TO DOCUMENT METADATA ---
            if device_info:
                full_meta['device_fingerprint'] = device_info
            # --------------------------------------------

            metadata_to_save = json.dumps(full_meta)
        else:
            # For PAN, use the simpler string format but we lose structured device info here
            # unless we switch PAN to JSON metadata too. For now, sticking to existing logic.
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
        
        # --- AUDIT LOGGING START ---
        new_doc_id = cur_write.lastrowid
        
        # Log the upload event
        audit_details = f"Filename: {filename} | Extracted Name: {extracted.get('name','N/A')}"
        log_audit_event(cur_write, 'USER', user_id, 'DOC_UPLOADED', audit_details, user_id, new_doc_id)
        
        # Log Fraud Alerts if any
        if manipulation_verdict == 'SUSPICIOUS' or pattern_verdict == 'SUSPICIOUS':
            log_audit_event(cur_write, 'SYSTEM', None, 'FRAUD_ALERT_CREATED', f"Suspicious pattern detected in doc {new_doc_id}", user_id, new_doc_id)
            
        if visual_forgery_verdict == 'FORGERY_DETECTED':
            log_audit_event(cur_write, 'SYSTEM', None, 'FRAUD_ALERT_CREATED', f"Visual forgery detected in doc {new_doc_id}", user_id, new_doc_id)
        # --- AUDIT LOGGING END ---

        db.commit()
        return jsonify({
            "status":"success",
            "message":"Document uploaded and logged", 
            "device_logged": True if device_info else False
        }), 200
    except Exception as e:
        current_app.logger.error(f"DB write error during upload: {e}")
        return jsonify({"status":"error","message":f"DB write error: {e}"}), 500
    finally:
        cur_write.close()
        db.close()

@user_bp.route('/verify_identity/<int:user_id>', methods=['POST'])
def api_verify_identity(user_id):
    db = get_db()
    if not db:
        return jsonify({"status":"error","message":"DB error"}), 500
        
    cur = db.cursor(dictionary=True)
    cur_write = db.cursor()
    
    try:
        # --- NEW: CAPTURE DEVICE INFO & RUN FRAUD CHECKS ---
        current_device = get_device_info()
        fraud_risk_flags = []
        
        if check_multiple_uploads_same_device(current_device["device_hash"]):
            fraud_risk_flags.append("HIGH RISK: Multiple uploads from same device in short duration")

        if check_multiple_devices_same_user(user_id):
            fraud_risk_flags.append("SUSPICIOUS: User accessing from multiple devices recently")
        # ---------------------------------------------------

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
        
        # Get latest Aadhaar and PAN
        aadhaar = next((x for x in docs if x['doc_type']=='AADHAAR'), None)
        pan = next((x for x in docs if x['doc_type']=='PAN'), None)
        dl = next((x for x in docs if x['doc_type']=='DRIVING_LICENSE'), None)

        if not (aadhaar and pan):
            return jsonify({"status": "pending", "message": "Verification requires both Aadhaar and PAN."}), 200
        
        # 3. Face Matching Check
        face_match_result = {"status": "N/A", "match_percent": "0%", "error": "Live photo missing."}
        if has_live_photo and aadhaar:
            AADHAAR_DOC_PATH = os.path.join(UPLOAD_FOLDER, aadhaar['filename'])
            LIVE_PHOTO_PATH = os.path.join(LIVE_PHOTO_FOLDER, f"user_{user_id}_live.jpg") 

            if os.path.exists(AADHAAR_DOC_PATH) and os.path.exists(LIVE_PHOTO_PATH):
                face_match_result = FACE_MATCHER_SERVICE.match_faces(AADHAAR_DOC_PATH, LIVE_PHOTO_PATH)
            else:
                current_app.logger.warning(f"Face match files missing: Aadhaar: {os.path.exists(AADHAAR_DOC_PATH)}, Live: {os.path.exists(LIVE_PHOTO_PATH)}")
                face_match_result = {"status": "N/A", "match_percent": "0%", "error": "Missing ID or Live photo file."}

        # 4. Validation & Scoring Checks
        aadhaar_validity = check_aadhaar_validity(aadhaar['extracted_id'])
        pan_validity = check_pan_validity(pan['extracted_id'])
        dl_validity = check_dl_validity(dl['extracted_id']) if dl else None
        
        cross_field_consistency = check_cross_field_consistency(aadhaar, pan)
        match_result = compare_names(aadhaar['extracted_name'], pan['extracted_name'])

        # Aggregate verdicts from key docs
        overall_manipulation = 'SUSPICIOUS' if any(extract_verdict_from_metadata(d.get('metadata', ''), 'Manipulation') == 'SUSPICIOUS' for d in [aadhaar, pan]) else 'CLEAN'
        overall_pattern = 'SUSPICIOUS' if any(extract_verdict_from_metadata(d.get('metadata', ''), 'Pattern') == 'SUSPICIOUS' for d in [aadhaar, pan]) else 'CLEAN'
        overall_visual_forgery = 'FORGERY_DETECTED' if any(extract_verdict_from_metadata(d.get('metadata', ''), 'Visual Forgery') == 'FORGERY_DETECTED' for d in [aadhaar, pan]) else 'CLEAN'

        fraud_score = calculate_fraud_score(
            aadhaar_validity, pan_validity, dl_validity, 
            match_result, False, 
            manipulation_verdict=overall_manipulation,
            cross_field_consistency=cross_field_consistency,
            pattern_verdict=overall_pattern,
            visual_forgery_verdict=overall_visual_forgery,
            face_match_result=face_match_result
        )
        
        # 5. AML Check
        aml_result = check_aml_blacklist(user_name, aadhaar['extracted_id'])

        # --- NEW: CAPTURE & LOG SPECIFIC FRAUD FACTORS (NAME/DOB MISMATCH) ---
        if fraud_score.get('factors'):
            for factor in fraud_score['factors']:
                # Example factor: "HIGH: Name match mismatch (60%)"
                if any(k in factor for k in ['HIGH', 'CRITICAL', 'MED']):
                    # Clean up string for log
                    detail_msg = f"Verification Risk: {factor}"
                    log_audit_event(cur_write, 'SYSTEM', None, 'FRAUD_ALERT_CREATED', detail_msg, user_id, None)
        # ---------------------------------------------------------------------

        # 6. Auto Decision
        new_status = get_auto_verification_decision(fraud_score, aml_result, face_match_result)
        
        # --- INTEGRATE DEVICE FRAUD RISKS INTO DECISION ---
        # If device fraud checks failed, force status to PENDING or REJECTED even if documents look good
        if fraud_risk_flags:
            fraud_score['risk_flags'] = fraud_risk_flags
            if new_status == 'VERIFIED':
                new_status = 'PENDING' # Downgrade to pending for manual review
                fraud_score['level'] = 'Review Needed (Device Risk)'
                
            # Log device fraud alert to audit trail
            log_audit_event(cur_write, 'SYSTEM', None, 'FRAUD_ALERT_CREATED', f"Device Risk Flags: {', '.join(fraud_risk_flags)}", user_id, None)
        # --------------------------------------------------

        # 7. Update Status (Batch update all key docs)
        cur_write.execute("UPDATE documents SET status=%s WHERE user_id=%s AND doc_type IN ('AADHAAR', 'PAN', 'DRIVING_LICENSE', 'UTILITY_BILL', 'AADHAAR_BACK')", (new_status, user_id))
        
        # 8. Store final fraud/AML metadata (Update user verification status)
        final_meta = {
            "fraud_score": fraud_score,
            "aml_result": aml_result,
            "face_match_result": face_match_result,
            "device_risks": fraud_risk_flags,  # <-- Added device risks here
            "final_status": new_status,
            "updated_at": datetime.now().isoformat()
        }
        cur_write.execute("UPDATE users SET verification_status=%s, verification_metadata=%s WHERE id=%s", (new_status, json.dumps(final_meta), user_id))

        # Audit Log for Decision
        log_audit_event(cur_write, 'SYSTEM', None, 'VERIFICATION_DECISION', f"System Auto-Decision: {new_status} (Score: {fraud_score.get('score', 'N/A')})", user_id, None)

        db.commit()
        
        return jsonify({
            "status": new_status.lower(),
            "message": f"Identity verification complete. Final status: {new_status}.",
            "risk_flags": fraud_risk_flags,
            "details": final_meta
        }), 200

    except Exception as e:
        db.rollback()
        current_app.logger.error(f"Verification Pipeline Error for user {user_id}: {e}")
        return jsonify({"status":"error","message":f"Verification failed: {e}"}), 500
    finally:
        cur.close()
        cur_write.close()
        db.close()

@user_bp.route('/chat_assistant', methods=['POST'])
def api_chat_assistant():
    """
    Smart KYC Assistant for users.
    Uses user docs + status as context and asks Gemini microservice.
    """
    data = request.get_json() or {}
    user_id = data.get("user_id")
    user_message = data.get("message", "").strip()

    if not user_id or not user_message:
        return jsonify({"success": False, "message": "user_id and message are required"}), 400

    db = get_db()
    if not db:
        return jsonify({"success": False, "message": "Database connection error"}), 500

    cur = db.cursor(dictionary=True)
    try:
        # 1. Fetch basic user info
        cur.execute("SELECT id, name, email, verification_status FROM users WHERE id=%s", (user_id,))
        user = cur.fetchone()
        if not user:
            return jsonify({"success": False, "message": "User not found"}), 404

        # 2. Fetch user documents
        cur.execute("SELECT * FROM documents WHERE user_id=%s ORDER BY uploaded_at DESC", (user_id,))
        docs = cur.fetchall()

        # 3. Build a compact text context for Gemini
        context_lines = []
        context_lines.append(f"User Name: {user['name']}")
        context_lines.append(f"User Email: {user['email']}")
        context_lines.append(f"Overall Verification Status: {user.get('verification_status', 'UNKNOWN')}")

        for d in docs:
            context_lines.append("\n--- Document ---")
            context_lines.append(f"Type: {d.get('doc_type')}")
            context_lines.append(f"Status: {d.get('status')}")
            context_lines.append(f"Extracted Name: {d.get('extracted_name')}")
            context_lines.append(f"Extracted ID: {d.get('extracted_id')}")
            context_lines.append(f"Extracted DOB: {d.get('extracted_dob')}")
            # Shorten OCR text to avoid sending huge payload
            ocr_preview = (d.get('ocr_text') or '')[:400]
            context_lines.append(f"OCR Preview: {ocr_preview}")
            meta = d.get('metadata')
            if meta:
                meta_preview = str(meta)[:400]
                context_lines.append(f"Metadata: {meta_preview}")

        kyc_context = "\n".join(context_lines)

    except Exception as e:
        current_app.logger.error(f"Chat assistant DB error: {e}")
        return jsonify({"success": False, "message": f"DB error: {e}"}), 500
    finally:
        cur.close()
        db.close()

    # 4. Call Gemini microservice
    try:
        resp = requests.post(
            "http://localhost:6000/chat",
            json={"message": user_message, "context": kyc_context},
            timeout=20
        )
        if resp.status_code != 200:
            return jsonify({"success": False, "message": "AI service error", "details": resp.text}), 502

        payload = resp.json()
        return jsonify({
            "success": True,
            "reply": payload.get("reply", "Sorry, I could not generate a response.")
        }), 200

    except Exception as e:
        current_app.logger.error(f"Chat assistant Gemini error: {e}")
        return jsonify({"success": False, "message": f"AI call failed: {e}"}), 500