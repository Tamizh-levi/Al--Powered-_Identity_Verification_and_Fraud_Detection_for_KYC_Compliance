import os
import re
import json
from flask import Blueprint, request, jsonify, send_file, current_app
from datetime import datetime, timedelta
import mysql.connector

# Local module imports
from config import UPLOAD_FOLDER, FACE_MATCHER_SERVICE, LIVE_PHOTO_FOLDER, ADMIN_USERNAME, ADMIN_PASSWORD
from db import get_db
from helpers import safe_jsonify, extract_verdict_from_metadata, validate_indian_address_via_api
from scoring_logic import check_aadhaar_validity, check_pan_validity, check_dl_validity, check_cross_field_consistency, calculate_fraud_score

# Name matching imports
from name_match import compare_names

# --- NEW: Fraud Analytics Import ---
from fraud_utils import get_user_device_risk_report

admin_bp = Blueprint('admin_routes', __name__, url_prefix='/api')

# --- Helper Functions ---

def log_admin_audit(cursor, action, details, related_user_id=None, related_doc_id=None):
    """Helper to log admin actions to audit_logs table."""
    try:
        cursor.execute("""
            INSERT INTO audit_logs (actor_type, actor_id, action, details, related_user_id, related_doc_id)
            VALUES ('ADMIN', 1, %s, %s, %s, %s)
        """, (action, details, related_user_id, related_doc_id))
        # Note: Hardcoded ADMIN ID 1 for now, can be dynamic if multi-admin auth is implemented
    except Exception as e:
        current_app.logger.error(f"Audit Log Error: {e}")

def _sync_user_status(cur, user_id):
    """
    Checks all documents for a user and updates the user's global verification_status.
    """
    try:
        cur.execute("SELECT doc_type, status FROM documents WHERE user_id=%s", (user_id,))
        docs = cur.fetchall() # Expecting dictionary cursor
        
        if not docs:
            return

        # 1. Check for immediate rejection
        if any(d['status'] == 'REJECTED' for d in docs):
            new_status = 'REJECTED'
        else:
            # 2. Check for full verification
            has_verified_aadhaar = any(d['doc_type'] == 'AADHAAR' and d['status'] == 'VERIFIED' for d in docs)
            has_verified_pan = any(d['doc_type'] == 'PAN' and d['status'] == 'VERIFIED' for d in docs)
            
            if has_verified_aadhaar and has_verified_pan:
                new_status = 'VERIFIED'
            else:
                new_status = 'PENDING'

        # 3. Update User Table
        cur.execute("UPDATE users SET verification_status=%s WHERE id=%s", (new_status, user_id))
        current_app.logger.info(f"Synced User {user_id} status to {new_status}")
        
    except Exception as e:
        current_app.logger.error(f"Error syncing user status for {user_id}: {e}")

def _api_update_doc_status(doc_id, status):
    """Internal helper to update document status AND sync user status."""
    db = get_db()
    if not db:
        return {"status":"error","message":"DB connection error"}, 500
    
    # Use dictionary=True to make data access easier
    cur = db.cursor(dictionary=True)
    try:
        # 1. Update Document Status
        cur.execute("UPDATE documents SET status=%s WHERE id=%s", (status, doc_id))
        
        # 2. Fetch User ID associated with this document
        cur.execute("SELECT user_id FROM documents WHERE id=%s", (doc_id,))
        row = cur.fetchone()
        
        if row:
            user_id = row['user_id']
            # 3. Sync User Status based on new document states
            _sync_user_status(cur, user_id)
            
            # 4. LOG AUDIT TRAIL
            action_type = "OVERRIDE_DECISION" if status == 'REJECTED' else "VERIFICATION_DECISION"
            details = f"Admin changed status to {status}"
            log_admin_audit(cur, action_type, details, user_id, doc_id)
            
        db.commit()
        return {"status":"success","message":f"Document {doc_id} set to {status}"}, 200
    except Exception as e:
        current_app.logger.error(f"Status update error for doc {doc_id}: {e}")
        return {"status":"error","message":str(e)}, 500
    finally:
        cur.close()
        db.close()

# --- ADMIN ROUTES ---

@admin_bp.route('/v1/admin_login', methods=['POST'])
@admin_bp.route('/admin_login', methods=['POST'])
def api_admin_login():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        return jsonify({
            "success": True,
            "message": "Admin login successful",
            "role": "admin"
        }), 200

    return jsonify({"success":False,"message":"Invalid admin credentials"}), 401

@admin_bp.route('/admin/dashboard', methods=['GET'])
@admin_bp.route('/v1/admin/dashboard', methods=['GET'])
def api_admin_dashboard():
    db = get_db()
    if not db:
        return jsonify({"success":False,"message":"Database connection error"}), 500
    cur = db.cursor(dictionary=True)
    try:
        # 1. Fetch Detailed User List
        cur.execute("""
            SELECT u.id as user_id, u.name as user_name, u.email, u.verification_status, u.has_live_photo,
                SUM(CASE WHEN d.doc_type = 'AADHAAR' THEN 1 ELSE 0 END) as aadhaar_count,
                SUM(CASE WHEN d.doc_type = 'PAN' THEN 1 ELSE 0 END) as pan_count,
                SUM(CASE WHEN d.doc_type = 'DRIVING_LICENSE' THEN 1 ELSE 0 END) as dl_count,
                SUM(CASE WHEN d.doc_type = 'UTILITY_BILL' THEN 1 ELSE 0 END) as utility_count,
                SUM(CASE WHEN d.status = 'PENDING' THEN 1 ELSE 0 END) as pending_count,
                MAX(d.uploaded_at) as last_upload_at
            FROM users u
            LEFT JOIN documents d ON u.id = d.user_id
            GROUP BY u.id, u.name, u.email, u.verification_status, u.has_live_photo
            ORDER BY u.id DESC
        """)
        users_list = cur.fetchall()

        # 2. Fetch Aggregate Stats for Dashboard Cards & Pie Chart
        
        # User Stats
        cur.execute("""
            SELECT 
                COUNT(*) as total_users,
                SUM(CASE WHEN verification_status IN ('APPROVED', 'VERIFIED') THEN 1 ELSE 0 END) as verified_users,
                SUM(CASE WHEN verification_status = 'REJECTED' THEN 1 ELSE 0 END) as rejected_users,
                SUM(CASE WHEN verification_status IN ('PENDING', 'NEW') THEN 1 ELSE 0 END) as pending_users
            FROM users
        """)
        user_stats = cur.fetchone()

        # Document Stats
        cur.execute("""
            SELECT 
                SUM(CASE WHEN status IN ('APPROVED', 'VERIFIED') THEN 1 ELSE 0 END) as documents_passed
            FROM documents
        """)
        doc_stats = cur.fetchone()

        # Calculate "Finished" (Verified + Rejected)
        total_verified = user_stats['verified_users'] if user_stats['verified_users'] else 0
        total_rejected = user_stats['rejected_users'] if user_stats['rejected_users'] else 0
        total_pending = user_stats['pending_users'] if user_stats['pending_users'] else 0
        total_finished = total_verified + total_rejected
        
        documents_passed = doc_stats['documents_passed'] if doc_stats and doc_stats['documents_passed'] else 0

        # Construct the stats object
        stats = {
            "total_users": user_stats['total_users'],
            "total_documents_passed": int(documents_passed),
            "total_pending_verifications": int(total_pending),
            "total_finished_verifications": int(total_finished),
            "pie_chart_data": {
                "verified": int(total_verified),
                "rejected": int(total_rejected),
                "pending": int(total_pending)
            }
        }

        return jsonify({
            "success": True, 
            "users": users_list,
            "stats": stats
        }), 200

    except Exception as e:
        current_app.logger.error(f"Admin dashboard error: {e}")
        return jsonify({"success":False,"message":str(e)}), 500
    finally:
        cur.close()
        db.close()

@admin_bp.route('/admin/alerts', methods=['GET'])
@admin_bp.route('/v1/admin/alerts', methods=['GET'])
def api_admin_alerts():
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
        current_app.logger.error(f"Admin alerts error: {e}")
        return jsonify({"success":False,"message":str(e)}), 500
    finally:
        cur.close()
        db.close()

@admin_bp.route('/admin/review/<int:user_id>', methods=['GET','POST'])
@admin_bp.route('/v1/admin/review/<int:user_id>', methods=['GET','POST'])
def api_admin_review(user_id):
    db = get_db()
    if not db:
        return jsonify({"status":"error","message":"DB error"}), 500
    cur = db.cursor(dictionary=True)
    try:
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
                cur_write = db.cursor(dictionary=True)
                
                # Update PAN name, reset status to PENDING for re-verification
                cur_write.execute("UPDATE documents SET extracted_name=%s, status='PENDING' WHERE id=%s",
                                 (corrected_name, pan_doc_id))
                
                # Sync User Status
                _sync_user_status(cur_write, user_id)
                
                # Log Audit
                log_admin_audit(cur_write, 'OVERRIDE_DECISION', f"Manual Correction: PAN name set to {corrected_name}", user_id, pan_doc_id)
                
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
            # Use helper to reliably extract verdicts
            d['manipulation_verdict'] = extract_verdict_from_metadata(d.get('metadata', ''), 'Manipulation')
            d['pattern_verdict'] = extract_verdict_from_metadata(d.get('metadata', ''), 'Pattern')
            d['visual_forgery_verdict'] = extract_verdict_from_metadata(d.get('metadata', ''), 'Visual Forgery')
            
            # Populate metadata_json for display if available
            # UPDATED: Added AADHAAR_BACK to ensure metadata is parsed correctly
            if d.get('doc_type') in ('DRIVING_LICENSE', 'AADHAAR', 'UTILITY_BILL', 'AADHAAR_BACK') and d.get('metadata'):
                 try:
                      pj = json.loads(d['metadata'])
                      d['metadata_json'] = pj
                 except Exception:
                      pass

        # Pick most recent non-rejected docs for core checks
        aadhaar = next((x for x in docs if x['doc_type']=='AADHAAR' and x['status']!='REJECTED'), None) or next((x for x in docs if x['doc_type']=='AADHAAR'), None)
        pan = next((x for x in docs if x['doc_type']=='PAN' and x['status']!='REJECTED'), None) or next((x for x in docs if x['doc_type']=='PAN'), None)
        dl = next((x for x in docs if x['doc_type']=='DRIVING_LICENSE' and x['status']!='REJECTED'), None) or next((x for x in docs if x['doc_type']=='DRIVING_LICENSE'), None)
        
        # NOTE: Added UTILITY_BILL selection here
        utility = next((x for x in docs if x['doc_type']=='UTILITY_BILL' and x['status']!='REJECTED'), None) or next((x for x in docs if x['doc_type']=='UTILITY_BILL'), None)

        pan_name_for_match = pan['extracted_name'] if pan else 'N/A'
        if request.method == 'POST' and action in ('test_match','save_and_verify') and corrected_name:
            # Use corrected name for match calculation in POST request
            pan_name_for_match = corrected_name

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
            AADHAAR_DOC_PATH = os.path.join(UPLOAD_FOLDER, aadhaar['filename'])
            LIVE_PHOTO_PATH = os.path.join(LIVE_PHOTO_FOLDER, f"user_{user_id}_live.jpg") 

            if os.path.exists(AADHAAR_DOC_PATH) and os.path.exists(LIVE_PHOTO_PATH):
                face_match_result = FACE_MATCHER_SERVICE.match_faces(AADHAAR_DOC_PATH, LIVE_PHOTO_PATH)
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
            # Include utility in the overall check
            all_docs = [d for d in [aadhaar, pan, dl, utility] if d]
            overall_manipulation = 'SUSPICIOUS' if any(d.get('manipulation_verdict') == 'SUSPICIOUS' for d in all_docs) else 'CLEAN'
            overall_pattern = 'SUSPICIOUS' if any(d.get('pattern_verdict') == 'SUSPICIOUS' for d in all_docs) else 'CLEAN'
            overall_visual_forgery = 'FORGERY_DETECTED' if any(d.get('visual_forgery_verdict') == 'FORGERY_DETECTED' for d in all_docs) else 'CLEAN'
            
            fraud_score = calculate_fraud_score(
                aadhaar_validity, pan_validity, dl_validity, 
                match_result, False, 
                manipulation_verdict=overall_manipulation,
                cross_field_consistency=cross_field_consistency,
                pattern_verdict=overall_pattern,
                visual_forgery_verdict=overall_visual_forgery,
                face_match_result=face_match_result
            )
            
            # Update match result verdict based on high risk flag
            if fraud_score['level']=='High Risk' and match_result:
                match_result['verdict'] = f"HIGH RISK (Score: {fraud_score['score']})"
                match_result['color'] = fraud_score['color']
            elif match_result and match_result.get('verdict')=='Strong Match' and aadhaar_validity and pan_validity and aadhaar_validity['status']=='VALID' and pan_validity['status']=='VALID':
                match_result['verdict'] = "STRONG MATCH (Automated Green Flag)"
                match_result['color'] = "green"

        # --- NEW: Fetch Device Risk Report ---
        device_risk_report = get_user_device_risk_report(user_id)
        # -------------------------------------

        resp = {
            "status":"success",
            "user_info": user_info,
            "docs": docs,
            "aadhaar_doc": aadhaar,
            "pan_doc": pan,
            "dl_doc": dl,
            "utility_doc": utility, # NOTE: Passed utility_doc to frontend
            "aadhaar_validity": aadhaar_validity,
            "pan_validity": pan_validity,
            "dl_validity": dl_validity,
            "match_result": match_result,
            "fraud_score": fraud_score,
            "cross_field_consistency": cross_field_consistency, 
            "face_match_result": face_match_result,
            "overall_status": overall_status,
            # Include device risks in response
            "device_risk_report": device_risk_report
        }
        if request.method == 'POST' and action == 'save_and_verify':
            resp['message'] = f"PAN name updated to {corrected_name} and marked for re-verification"
        return jsonify(resp), 200
    except Exception as e:
        current_app.logger.error(f"Review API Error for user {user_id}: {e}")
        return jsonify({"status":"error","message":str(e)}), 500
    finally:
        cur.close()
        db.close()

# Admin actions (verify/reject/delete)
@admin_bp.route('/admin/verify_doc/<int:doc_id>', methods=['POST'])
@admin_bp.route('/v1/admin/verify_doc/<int:doc_id>', methods=['POST'])
def api_verify_doc(doc_id):
    res, code = _api_update_doc_status(doc_id, 'VERIFIED')
    return jsonify(res), code

@admin_bp.route('/admin/reject_doc/<int:doc_id>', methods=['POST'])
@admin_bp.route('/v1/admin/reject_doc/<int:doc_id>', methods=['POST'])
def api_reject_doc(doc_id):
    res, code = _api_update_doc_status(doc_id, 'REJECTED')
    return jsonify(res), code

@admin_bp.route('/admin/delete_doc/<int:doc_id>', methods=['DELETE'])
@admin_bp.route('/v1/admin/delete_doc/<int:doc_id>', methods=['DELETE'])
def api_delete_doc(doc_id):
    db = get_db()
    if not db:
        return jsonify({"status":"error","message":"DB error"}), 500
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT filename, user_id FROM documents WHERE id=%s", (doc_id,))
        doc = cur.fetchone()
        if not doc:
            return jsonify({"status":"error","message":"Document not found"}), 404
        
        filename = doc['filename']
        user_id = doc['user_id']
        
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        if os.path.exists(file_path):
            os.remove(file_path)
            
        cur_del = db.cursor()
        cur_del.execute("DELETE FROM documents WHERE id=%s", (doc_id,))
        
        # Log Audit
        log_admin_audit(cur_del, 'DELETE_DOC', f"Deleted document {doc_id} ({filename})", user_id, doc_id)
        
        db.commit()
        cur_del.close()
        return jsonify({"status":"success","message":"Document deleted"}), 200
    except Exception as e:
        current_app.logger.error(f"Document delete error for doc {doc_id}: {e}")
        return jsonify({"status":"error","message":str(e)}), 500
    finally:
        cur.close()
        db.close()

@admin_bp.route('/admin/uploads/<path:filename>', methods=['GET'])
def serve_upload(filename):
    """Serves uploaded documents (for admin review)."""
    path = os.path.join(UPLOAD_FOLDER, filename)
    if os.path.exists(path):
        return send_file(path)
    return jsonify({"status":"error","message":"File not found"}), 404

# --- NEW: Address Validation Endpoint ---
@admin_bp.route('/admin/validate_address', methods=['POST'])
@admin_bp.route('/v1/admin/validate_address', methods=['POST'])
def api_validate_address():
    """
    Admin triggered validation for extracted addresses.
    Uses postal code API to verify state and pin existence.
    """
    data = request.get_json() or {}
    address_text = data.get('address')
    doc_id = data.get('doc_id') # Optional, useful for logging/history

    if not address_text:
        return jsonify({"status": "error", "message": "Address text is required"}), 400

    # Perform Validation via Helper
    validation_result = validate_indian_address_via_api(address_text)
    
    if doc_id:
        current_app.logger.info(f"Address Validation performed for Doc {doc_id}: {validation_result['status']}")

    return jsonify({
        "success": True,
        "data": validation_result
    }), 200

# --- NEW: Audit Trail Endpoint ---
@admin_bp.route('/v1/audit_trail', methods=['GET'])
def api_audit_trail():
    """
    Retrieves audit logs with filtering capability.
    Filters: user_name, doc_name (filename/type), start_date, end_date, action
    UPDATED: Now filters by text names using LEFT JOINs instead of IDs.
    """
    # Accept Name based filters now
    user_name = request.args.get('user_name')
    doc_name = request.args.get('doc_name')
    
    action = request.args.get('action')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    db = get_db()
    if not db:
        return jsonify({"success": False, "message": "Database connection error"}), 500
        
    cur = db.cursor(dictionary=True)
    try:
        # Base query with Joins
        query = """
            SELECT a.*, u.name as user_name, d.filename as doc_filename, d.doc_type as doc_type
            FROM audit_logs a
            LEFT JOIN users u ON a.related_user_id = u.id
            LEFT JOIN documents d ON a.related_doc_id = d.id
            WHERE 1=1
        """
        params = []
        
        # Add dynamic filters (Using LIKE for fuzzy search)
        if user_name:
            query += " AND u.name LIKE %s"
            params.append(f"%{user_name}%")
            
        if doc_name:
            # Flexible search: matches filename OR document type (e.g., 'Aadhaar')
            query += " AND (d.filename LIKE %s OR d.doc_type LIKE %s)"
            params.append(f"%{doc_name}%")
            params.append(f"%{doc_name}%")
            
        if action:
            query += " AND a.action = %s"
            params.append(action)
            
        if start_date:
            query += " AND a.timestamp >= %s"
            params.append(start_date)
            
        if end_date:
            try:
                end_dt = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
                query += " AND a.timestamp < %s"
                params.append(end_dt.strftime('%Y-%m-%d'))
            except ValueError:
                pass 
                
        # Order by newest first
        query += " ORDER BY a.timestamp DESC LIMIT 100"
        
        cur.execute(query, tuple(params))
        logs = cur.fetchall()
        
        # Post-process results
        results = []
        for log in logs:
            actor_display = "UNKNOWN"
            if log.get('actor_type') == 'SYSTEM':
                actor_display = "SYSTEM"
            elif log.get('actor_type') == 'ADMIN':
                actor_display = f"ADMIN#{log.get('actor_id')}"
            elif log.get('actor_type') == 'USER':
                actor_display = f"USER#{log.get('actor_id')}"
                
            results.append({
                "id": log['id'],
                "timestamp": log['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if log['timestamp'] else '',
                "full_timestamp": log['timestamp'].isoformat() if log['timestamp'] else '',
                "actor": actor_display,
                "action": log['action'],
                "details": log['details'] or '',
                # Add context info if available from join
                "user_name_match": log.get('user_name'),
                "doc_name_match": log.get('doc_filename')
            })
            
        return jsonify({"success": True, "logs": results}), 200
        
    except mysql.connector.Error as err:
        if err.errno == 1146: 
            return jsonify({"success": True, "logs": [], "message": "Audit table not initialized."}), 200
        current_app.logger.error(f"Audit Trail Error: {err}")
        return jsonify({"success": False, "message": str(err)}), 500
    finally:
        cur.close()
        db.close()

# --- NEW: FRAUD ALERTS ENDPOINT ---
@admin_bp.route('/v1/fraud_alerts', methods=['GET'])
def api_fraud_alerts():
    """
    Dedicated endpoint to fetch ONLY fraud alerts.
    Enriches data with severity level based on keyword analysis.
    """
    db = get_db()
    if not db:
        return jsonify({"success": False, "message": "Database connection error"}), 500
        
    cur = db.cursor(dictionary=True)
    try:
        # Query audit logs for fraud events only
        query = """
            SELECT a.*, u.name as user_name, u.email as user_email
            FROM audit_logs a
            LEFT JOIN users u ON a.related_user_id = u.id
            WHERE a.action = 'FRAUD_ALERT_CREATED'
            ORDER BY a.timestamp DESC
            LIMIT 50
        """
        cur.execute(query)
        logs = cur.fetchall()
        
        results = []
        for log in logs:
            # Determine Severity Logic
            details = (log['details'] or '').upper()
            severity = 'MEDIUM' # Default
            
            if 'CRITICAL' in details or 'FORGERY' in details:
                severity = 'CRITICAL'
            elif 'HIGH' in details or 'MISMATCH' in details:
                severity = 'HIGH'
                
            results.append({
                "id": log['id'],
                "timestamp": log['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                "user_name": log['user_name'] or 'Unknown User',
                "user_email": log['user_email'] or 'N/A',
                "details": log['details'],
                "severity": severity
            })
            
        return jsonify({"success": True, "alerts": results}), 200
        
    except Exception as e:
        current_app.logger.error(f"Fraud Alert API Error: {e}")
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        cur.close()
        db.close()

# --- NEW: FULL FRAUD DETAIL REPORT ENDPOINT ---
@admin_bp.route('/v1/admin/fraud_detailed_report', methods=['GET'])
def api_admin_fraud_detailed_report():
    """
    Comprehensive Fraud Data Aggregation for Admin UI.
    Fetches high-risk users and unpacks all metadata (Score, Forgery, Device, Address).
    """
    db = get_db()
    if not db:
        return jsonify({"success": False, "message": "Database connection error"}), 500
        
    cur = db.cursor(dictionary=True)
    try:
        # 1. Select Users who have gone through verification (have metadata)
        # We prioritize fetching users who have some verification metadata (processed users)
        query = """
            SELECT u.id, u.name, u.email, u.verification_status, u.verification_metadata, u.has_live_photo
            FROM users u
            WHERE u.verification_metadata IS NOT NULL
            ORDER BY u.id DESC
            LIMIT 50
        """
        cur.execute(query)
        users = cur.fetchall()
        
        detailed_reports = []
        
        for user in users:
            user_id = user['id']
            
            # --- A. Parse User Verification Metadata (The Core Logic) ---
            # This handles: Score Breakdown, Component Scores, Risk Level
            ver_meta = {}
            if user['verification_metadata']:
                try:
                    ver_meta = json.loads(user['verification_metadata'])
                except:
                    ver_meta = {}

            fraud_score_data = ver_meta.get('fraud_score', {})
            face_match_data = ver_meta.get('face_match_result', {})
            aml_data = ver_meta.get('aml_result', {})
            
            # --- B. Fetch Document Details (The Evidence) ---
            # This handles: ID Validity, Forgery Analysis, Visual Verdicts
            cur.execute("""
                SELECT doc_type, status, metadata, extracted_name, extracted_id 
                FROM documents WHERE user_id = %s
            """, (user_id,))
            docs = cur.fetchall()
            
            doc_analysis = {
                "aadhaar": {"validity": "N/A", "forgery": "N/A", "details": []},
                "pan": {"validity": "N/A", "forgery": "N/A", "details": []},
                "dl": {"validity": "N/A", "forgery": "N/A", "details": []}
            }
            
            suspicious_address_lines = []
            
            for d in docs:
                dtype = d['doc_type'].lower()
                d_meta = {}
                if d['metadata']:
                    try:
                        d_meta = json.loads(d['metadata']) if '{' in str(d['metadata']) else {}
                    except:
                        pass
                
                # 1. Verdicts
                manipulation = d_meta.get('manipulation_details', {}).get('verdict', 'UNKNOWN')
                visual_forgery = d_meta.get('visual_forgery_verdict', 'UNKNOWN')
                
                # 2. Map to response structure if it's one of our core types
                # Note: d['doc_type'] might be 'DRIVING_LICENSE' so we need to be careful with keys
                key = None
                if dtype == 'aadhaar': key = 'aadhaar'
                elif dtype == 'pan': key = 'pan'
                elif dtype == 'driving_license': key = 'dl'
                
                if key:
                    # Validity implies the document was accepted/verified by logic
                    doc_analysis[key]['validity'] = d['status'] 
                    doc_analysis[key]['forgery'] = f"Man: {manipulation} | Vis: {visual_forgery}"
                    
                    # Detailed Reasons
                    reasons = []
                    if 'SUSPICIOUS' in str(manipulation):
                        reasons.append(f"{key.upper()}: Text manipulation detected via NLP")
                    if 'FORGERY_DETECTED' in str(visual_forgery):
                        reasons.append(f"{key.upper()}: Visual artifacts/Photoshop traces detected")
                    if d_meta.get('is_low_res'):
                        reasons.append(f"{key.upper()}: Image resolution too low for accurate forensics")
                    
                    doc_analysis[key]['details'] = reasons
                    
                # 3. Address Extraction for analysis (Looking for short/junk addresses)
                if 'address' in d_meta:
                    addr = d_meta['address']
                    if len(str(addr)) < 10 or "SAMPLE" in str(addr).upper():
                        suspicious_address_lines.append(f"{d['doc_type']}: {addr} (Too Short/Sample)")
            
            # --- C. Device Fingerprint History ---
            # Handles: Repeat uploads, Device history
            device_report = get_user_device_risk_report(user_id)
            
            # --- D. Construct the Final Object ---
            report_item = {
                "user_id": user_id,
                "user_name": user['name'],
                "current_status": user['verification_status'],
                
                # 1. ID Validity
                "id_validity": {
                    "aadhaar_status": doc_analysis['aadhaar']['validity'],
                    "pan_status": doc_analysis['pan']['validity'],
                    "dl_status": doc_analysis['dl']['validity']
                },
                
                # 2. Forgery Analysis
                "forgery_analysis": {
                    "aadhaar_verdict": doc_analysis['aadhaar']['forgery'],
                    "pan_verdict": doc_analysis['pan']['forgery'],
                    "reasons": doc_analysis['aadhaar']['details'] + doc_analysis['pan']['details'] + doc_analysis['dl']['details']
                },
                
                # 3. Risk Score & Breakdown
                "risk_profile": {
                    "total_score": fraud_score_data.get('score', 0),
                    "risk_level": fraud_score_data.get('level', 'Unknown'),
                    "explanation": fraud_score_data.get('factors', []), # "Why the verdict was given"
                    "component_scores": {
                        "name_match": "Review" if "Name Match" in str(fraud_score_data.get('factors')) else "Good", 
                        "face_match": face_match_data.get('match_percent', 'N/A'),
                        "cross_field": "Inconsistent" if "Mismatch" in str(fraud_score_data.get('factors')) else "Consistent"
                    }
                },
                
                # 4. Device & Network
                "device_analysis": {
                    "risk_flags": device_report.get('risk_flags', []),
                    "history_summary": "See detailed logs" 
                },
                
                # 5. Address Analysis
                "address_analysis": {
                    "suspicious_lines": suspicious_address_lines,
                    "is_blocked": "Yes" if aml_data.get('status') == 'HIT' else "No" 
                }
            }
            
            detailed_reports.append(report_item)
            
        return jsonify({"success": True, "reports": detailed_reports}), 200

    except Exception as e:
        current_app.logger.error(f"Fraud Detailed Report Error: {e}")
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        cur.close()
        db.close()