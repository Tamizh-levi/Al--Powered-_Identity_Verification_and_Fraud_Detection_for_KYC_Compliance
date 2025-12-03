import json
import re
import requests  # Added for API calls
from datetime import datetime
import datetime as dt
import random
from typing import Dict, Any, Optional

# NLP / text understanding imports
from smart_text_utils import normalize_name, normalize_address


def safe_jsonify(obj):
    """Helper to ensure JSON serializable (handles bytes, datetime objects)."""
    def convert(o):
        if isinstance(o, bytes):
            return o.decode('utf-8', errors='ignore')
        if isinstance(o, datetime):
            return o.isoformat()
        return o
    return json.loads(json.dumps(obj, default=convert))


def parse_dob(dob_str: str) -> Optional[dt.date]:
    """
    Attempt to parse DOB string (D/M/Y or D-M-Y or YYYY) into a date object.
    Returns None if parsing fails.
    """
    if not dob_str or dob_str == 'N/A':
        return None

    formats = ['%d/%m/%Y', '%d-%m-%Y', '%Y']
    for fmt in formats:
        try:
            return datetime.strptime(dob_str, fmt).date()
        except ValueError:
            continue

    return None


# CONCEPTUAL: Visual Forgery Detection Simulation (CNN/GNN Signals)
def get_visual_forgery_signal(img_bytes: bytes) -> str:
    """
    Conceptual simulation of calling an external CNN/GNN model
    for visual forgery detection (e.g., splicing, cloning, template overlay).
    """
    # Simulate a low chance of forgery detection for testing
    if random.randint(1, 100) <= 5:  # 5% chance of suspected forgery
        return "FORGERY_DETECTED"
    return "CLEAN"


# AML Rule Engine
def check_aml_blacklist(name: str, id_number: str) -> Dict[str, Any]:
    """
    Conceptual check against an internal or external AML/Sanctions list.
    """
    normalized_name = normalize_name(name)

    # Simple simulation: Check for a suspicious pattern in name/ID
    if "SATAN" in normalized_name or id_number.endswith('00013'):
        return {"aml_status": "MATCH", "reason": "Blacklist match (high-risk pattern)."}

    return {"aml_status": "CLEAN", "reason": "No match found."}


def extract_verdict_from_metadata(doc_metadata: str, key: str) -> str:
    """Extracts a specific verdict (e.g., Manipulation) from the document metadata string."""
    if not doc_metadata:
        return 'CLEAN'

    # Try parsing JSON first for newer docs
    try:
        metadata_json = json.loads(doc_metadata)

        if key == 'Manipulation':
            return metadata_json.get('manipulation_details', {}).get('verdict', 'CLEAN')

        if key == 'Pattern':
            return metadata_json.get('pattern_details', {}).get('verdict', 'CLEAN')

        if key == 'Visual Forgery':
            return metadata_json.get('visual_forgery_verdict', 'CLEAN')

    except json.JSONDecodeError:
        pass  # fallback

    # Regex fallback for legacy PAN/old docs
    match = re.search(fr'{key}:\s*(\w+)', doc_metadata)
    return match.group(1) if match else 'CLEAN'


# --- NEW: Address Validation Logic ---
def validate_indian_address_via_api(address_text: str) -> Dict[str, Any]:
    """
    Validates an address string against the Indian Postal API.
    Checks for:
    1. Presence of a valid 6-digit Pincode.
    2. Existence of that Pincode in the postal database.
    3. Mismatch between the State in the address text vs the State linked to the Pincode.
    """
    if not address_text or len(address_text) < 5:
        return {"status": "INVALID", "reason": "Address text too short or empty", "details": {}}

    # 1. Extract Pincode (6 digits, allowing for optional space 600 001)
    pin_match = re.search(r'\b(\d{3})\s?(\d{3})\b', address_text)
    if not pin_match:
        return {"status": "WARNING", "reason": "No Pincode found in address text", "details": {}}
    
    pincode = f"{pin_match.group(1)}{pin_match.group(2)}"

    # 2. Call Indian Postal API
    try:
        # ADDED: Browser-like headers to prevent blocking (403/10054 errors)
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Accept": "application/json",
        }
        
        # Using the public API provided by api.postalpincode.in with increased timeout
        response = requests.get(
            f"https://api.postalpincode.in/pincode/{pincode}", 
            headers=headers,
            timeout=10
        )
        data = response.json()
        
    except Exception as e:
        return {"status": "ERROR", "reason": f"Postal API connection failed: {str(e)}", "details": {}}

    if not data or not isinstance(data, list):
        return {"status": "ERROR", "reason": "Invalid API response format", "details": {}}

    api_result = data[0]
    
    # 3. Check if Pincode exists
    if api_result.get("Status") != "Success":
        return {
            "status": "INVALID", 
            "reason": "Invalid PIN Code (Non-existent in Postal DB)", 
            "details": {"pincode": pincode}
        }

    post_office_data = api_result.get("PostOffice", [])
    if not post_office_data:
        return {"status": "INVALID", "reason": "No Post Office found for this PIN", "details": {}}

    # Get State and District from the first result (usually consistent across the PIN)
    official_state = post_office_data[0].get("State", "").upper()
    official_district = post_office_data[0].get("District", "").upper()

    # 4. Check for State Mismatch
    # Normalize OCR address for comparison
    norm_addr = address_text.upper().replace(".", "").replace(",", "")
    
    # Simple fuzzy logic for state abbreviations
    state_aliases = {
        "TAMIL NADU": ["TAMILNADU", "TN", "CHENNAI", "MADRAS"],
        "MAHARASHTRA": ["MH", "MUMBAI", "PUNE"],
        "KARNATAKA": ["KA", "BANGALORE", "BENGALURU"],
        "DELHI": ["DL", "NEW DELHI"],
        "UTTAR PRADESH": ["UP", "NOIDA"],
        "TELANGANA": ["TS", "HYDERABAD"],
        "KERALA": ["KL", "COCHIN", "KOCHI"],
        "ANDHRA PRADESH": ["AP", "VIJAYAWADA", "VISAKHAPATNAM"],
        "WEST BENGAL": ["WB", "KOLKATA", "CALCUTTA"]
    }

    state_match_found = False
    
    # Direct check
    if official_state in norm_addr:
        state_match_found = True
    else:
        # Alias check
        aliases = state_aliases.get(official_state, [])
        for alias in aliases:
            if alias in norm_addr:
                state_match_found = True
                break
    
    if not state_match_found:
        return {
            "status": "SUSPICIOUS",
            "reason": f"State Mismatch. PIN {pincode} is in '{official_state}', but address text does not match.",
            "details": {
                "pincode": pincode,
                "official_state": official_state,
                "official_district": official_district
            }
        }

    return {
        "status": "VALID",
        "reason": "Pincode exists and matches State context.",
        "details": {
            "pincode": pincode,
            "state": official_state,
            "district": official_district,
            "locality_count": len(post_office_data)
        }
    }