import re
from typing import Dict, Any, Optional
from datetime import datetime

from helpers import parse_dob

# --- ID Format Validation ---

def check_aadhaar_validity(aadhaar_id: str) -> Dict[str, str]:
    """Checks Aadhaar ID format (12 digits)."""
    if not aadhaar_id or aadhaar_id == 'N/A':
        return {"status": "INVALID", "message": "ID missing or not extracted."}
    if re.fullmatch(r'\d{12}', aadhaar_id.replace(" ", "")):
        return {"status": "VALID", "message": "Format matched 12 digits."}
    return {"status": "INVALID", "message": "Format mismatch (expected 12 digits)."}

def check_pan_validity(pan_id: str) -> Dict[str, str]:
    """Checks PAN ID format (AAAAANNNNA)."""
    if not pan_id or pan_id == 'N/A':
        return {"status": "INVALID", "message": "ID missing or not extracted."}
    if re.fullmatch(r'[A-Z]{5}\d{4}[A-Z]{1}', pan_id):
        return {"status": "VALID", "message": "Format matched AAAAANNNNA."}
    return {"status": "INVALID", "message": "Format mismatch (expected AAAAANNNNA)."}

def check_dl_validity(dl_id: str) -> Dict[str, str]:
    """Checks Driving License format (AA00XXXX...)."""
    if not dl_id or dl_id == 'N/A':
        return {"status": "INVALID", "message": "ID missing or not extracted."}
    clean_id = re.sub(r'[^A-Z0-9]', '', dl_id.upper())
    if re.fullmatch(r'[A-Z]{2}[0-9]{2}[0-9A-Z]{7,}', clean_id):
        return {"status": "VALID", "message": "Format matched Indian DL pattern (AA00XXXX...)."}
    return {"status": "INVALID", "message": "Format mismatch (expected AA00XXXX...)."}

# --- Cross-Field Consistency ---

def check_cross_field_consistency(aadhaar_doc: Optional[Dict[str, Any]], pan_doc: Optional[Dict[str, Any]]) -> Dict[str, str]:
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

# --- Fraud Score Calculation ---

def calculate_fraud_score(
    aadhaar_validity: Dict[str, str], 
    pan_validity: Dict[str, str], 
    dl_validity: Optional[Dict[str, str]], 
    match_result: Dict[str, str], 
    is_duplicate_submission: bool, 
    manipulation_verdict: str, 
    cross_field_consistency: Dict[str, str], 
    pattern_verdict: str, 
    visual_forgery_verdict: str, 
    face_match_result: Dict[str, Any]
) -> Dict[str, Any]:
    """Calculates the aggregated fraud risk score based on various factors."""
    risk_points = 0
    risk_factors = []

    # NEW: Risk factor for Face Match
    match_status = face_match_result.get('status')
    match_percent = face_match_result.get('match_percent', 'N/A')
    
    if match_status == 'LOW':
        risk_points += 50
        risk_factors.append(f"CRITICAL: Face Match Low Confidence ({match_percent}). Identity mismatch highly likely.")
    elif match_status == 'MEDIUM':
        risk_points += 20
        risk_factors.append(f"MED: Face Match Medium Confidence ({match_percent}). Requires manual review.")
    elif match_status == 'N/A':
        if "Missing ID or Live photo" in face_match_result.get('error', ''):
            risk_points += 10
            risk_factors.append("LOW: Face match could not be performed (missing live photo/ID image).")
    
    if is_duplicate_submission:
        risk_points += 40
        risk_factors.append("HIGH: Document ID previously submitted by another user.")
        
    # Risk factor for visual forgery detection
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


    if aadhaar_validity['status'] != 'VALID':
        risk_points += 10
        risk_factors.append(f"MED: Aadhaar ID format is invalid ({aadhaar_validity['message']}).")
    if pan_validity['status'] != 'VALID':
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
            
    # OCR confidence factor is assumed to be handled within manipulation_verdict for simplicity
    
    final_score = min(100, risk_points)
    
    if final_score <= 30:
        level, color = "Low Risk", "green"
    elif final_score <= 70:
        level, color = "Medium Risk", "yellow"
    else:
        level, color = "High Risk", "red"
        
    return {'score': f"{final_score}%", 'level': level, 'color': color, 'factors': risk_factors}

# --- Auto Verification Decision ---

def get_auto_verification_decision(fraud_score_data: Dict[str, Any], aml_result: Dict[str, Any], face_match_result: Dict[str, Any]) -> str:
    """
    Determines the final status based on the aggregated risk score, AML check, and Face Match.
    """
    try:
        score = int(fraud_score_data['score'].replace('%', ''))
    except ValueError:
        return "PENDING" # Cannot determine score, requires review
    
    # Hard rejection rules
    if score >= 80:
        return "REJECTED"
    if aml_result.get('aml_status') == 'MATCH':
        return "REJECTED"
    if face_match_result.get('status') == 'LOW': # Hard reject on low face match
        return "REJECTED"
        
    # Hard verification rules
    # Check if risk factors are zero and face match is high confidence
    if score <= 20 and len(fraud_score_data['factors']) == 0 and face_match_result.get('status') == 'HIGH':
        return "VERIFIED"
        
    # Anything else requires manual review
    return "PENDING"