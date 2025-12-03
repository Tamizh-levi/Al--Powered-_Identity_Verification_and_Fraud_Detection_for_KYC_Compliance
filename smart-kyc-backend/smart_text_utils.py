import re
from typing import Dict, Any, List
from collections import Counter

# A simple list of common noise words/titles for normalization
# Used for cleaning names extracted by OCR before comparison
NOISE_WORDS = ["MR", "MRS", "MISS", "DR", "SH", "SMT", "KUMAR", "DEVI", "S/O", "D/O", "W/O", "S/O:", "D/O:", "W/O:"]

# Address abbreviations for standardization
ADDRESS_ABBREVIATIONS = {
    "ST": "STREET", "RD": "ROAD", "LN": "LANE", "AVE": "AVENUE",
    "Bldg": "BUILDING", "Apt": "APARTMENT", "Fl": "FLOOR",
    "PO": "POST OFFICE", "PS": "POLICE STATION", "Dist": "DISTRICT",
    "H NO": "HOUSE NO", "H.NO": "HOUSE NO", "HNO": "HOUSE NO",
    "VILL": "VILLAGE", "COL": "COLONY", "Sec": "SECTOR",
    "M.I.D.C": "MIDC", "No.": "NUMBER", "NO.": "NUMBER",
    "#": "NUMBER"
}

def normalize_name(name: str) -> str:
    """
    Cleans and normalizes a name string for reliable comparison.
    """
    if not name:
        return ""

    # 1. Convert to uppercase
    name = name.upper()

    # 2. Remove non-alphabetic/non-space characters
    name = re.sub(r'[^A-Z\s]', ' ', name)

    # 3. Remove common noise words/titles using word boundaries
    for noise in NOISE_WORDS:
        name = re.sub(rf'\b{re.escape(noise)}\b', ' ', name).strip()

    # 4. Final clean up of multiple spaces resulting from removals
    name = re.sub(r'\s+', ' ', name).strip()

    return name

def normalize_address(address: str) -> str:
    """
    Cleans and standardizes an address string for comparison.
    """
    if not address:
        return ""
    
    address = address.upper()
    address = re.sub(r'[,\-]', ' ', address) # Replace common separators with spaces
    
    # Replace abbreviations using word boundaries for safety
    for abbr, full in ADDRESS_ABBREVIATIONS.items():
        address = re.sub(rf'\b{re.escape(abbr)}\b', full, address)
        
    # Remove all remaining non-alphanumeric characters (except space) and normalize whitespace
    address = re.sub(r'[^A-Z0-9\s]', ' ', address)
    address = re.sub(r'\s+', ' ', address).strip()
    
    return address

def check_text_manipulation(ocr_text: str) -> Dict[str, Any]:
    """
    Checks OCR text for simple indicators of potential manipulation or irregular formatting.
    """
    if not ocr_text:
        return {"verdict": "CLEAN", "reasons": ["No text extracted."], "is_clean": True}
        
    suspicious_chars = re.findall(r'[^\w\s\-\/\.:,]', ocr_text) 
    excessive_spacing = re.search(r' {4,}', ocr_text)
    
    if len(ocr_text) < 50:
        return {"verdict": "CLEAN", "reasons": ["Text too short to analyze for manipulation."], "is_clean": True}

    verdict = "CLEAN"
    reasons = []

    if suspicious_chars:
        verdict = "SUSPICIOUS"
        reasons.append(f"Found unusual non-alphanumeric characters: {', '.join(set(suspicious_chars[:5]))}")
    
    if excessive_spacing:
        verdict = "SUSPICIOUS"
        reasons.append("Irregular/excessive spacing detected (potential machine generation/edit).")
    
    if len(re.sub(r'[A-Z0-9\s]', '', ocr_text.upper())) > (len(ocr_text) * 0.20):
        verdict = "SUSPICIOUS"
        reasons.append("High ratio of special characters to text/numbers.")

    if not reasons:
        is_clean = True
    else:
        is_clean = False

    return {
        "verdict": verdict,
        "reasons": reasons,
        "is_clean": is_clean
    }

def check_complex_patterns(ocr_text: str) -> Dict[str, Any]:
    """
    Checks for structural patterns indicative of templated or generated text forgery.
    """
    if not ocr_text or len(ocr_text.split()) < 50:
        return {"verdict": "CLEAN", "details": "Text too short for structural analysis."}

    words = ocr_text.upper().split()
    word_lengths = [len(w) for w in words if w.isalnum()]
    
    if len(word_lengths) < 30:
        return {"verdict": "CLEAN", "details": "Not enough unique tokens for analysis."}
        
    # Heuristic 1: High Word Length Uniformity 
    length_counts = Counter(word_lengths)
    most_common_length, count = length_counts.most_common(1)[0]
    
    if count / len(word_lengths) > 0.5:
        return {"verdict": "SUSPICIOUS", "details": f"High word length uniformity (>{count/len(word_lengths)*100:.0f}% of words are length {most_common_length})."}

    # Heuristic 2: Low Lexical Diversity
    if len(set(words)) / len(words) < 0.3: 
        return {"verdict": "SUSPICIOUS", "details": "Unusually low ratio of unique words (potential template or repetitive text)."}
        
    return {"verdict": "CLEAN", "details": "Structural patterns appear normal."}


def detect_inconsistencies(extracted_entities: Dict[str, Any], user_data: Dict[str, str]) -> List[str]:
    """
    Placeholder for more advanced inconsistency checks.
    """
    return []