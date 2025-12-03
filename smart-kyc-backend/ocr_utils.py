import re
import unicodedata
from PIL import Image, ImageEnhance, ImageFilter
from io import BytesIO
from difflib import SequenceMatcher
import numpy as np
import cv2  # Import OpenCV for blur detection

# --- PILLOW/PIL COMPATIBILITY FIX ---
try:
    # Check if ANTIALIAS is missing and Image.Resampling exists (modern Pillow)
    if not hasattr(Image, 'ANTIALIAS') and hasattr(Image, 'Resampling'):
        Image.ANTIALIAS = Image.Resampling.LANCZOS 
    # Fallback for very old Pillow versions where Image.LANCZOS might be directly available
    elif not hasattr(Image, 'ANTIALIAS'):
        Image.ANTIALIAS = Image.LANCZOS 
except AttributeError:
    # Safest fallback if constants are completely different
    try:
        Image.ANTIALIAS = Image.LANCZOS
    except AttributeError:
        print("[WARN] Could not find Image.ANTIALIAS. Image scaling may fail.")
# --- END COMPATIBILITY FIX ---


# ============================================================
# OCR ENGINES
# ============================================================
try:
    import easyocr
    # Initialize EasyOCR for Tamil (ta) and English (en)
    easyocr_reader_ta = easyocr.Reader(['ta', 'en'])
    USE_EASYOCR = True
    print("[INFO] EasyOCR initialized successfully (ta+en).")
except Exception as e:
    print("[WARN] EasyOCR unavailable, falling back to Tesseract:", e)
    USE_EASYOCR = False

try:
    import pytesseract
    # pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
except Exception:
    pytesseract = None


# ============================================================
# IMAGE PREPROCESSING
# ============================================================
def preprocess_image(img):
    """Enhance brightness, contrast, and sharpness for OCR clarity."""
    # Increase contrast
    img = ImageEnhance.Contrast(img).enhance(1.8)
    # Increase brightness
    img = ImageEnhance.Brightness(img).enhance(1.3)
    # Apply sharpening filter
    img = img.filter(ImageFilter.SHARPEN)
    return img


# ============================================================
# IMAGE QUALITY CHECK
# ============================================================
BLUR_THRESHOLD = 50.0  
MIN_DIM = 600  

def check_image_quality(image_bytes) -> dict:
    """Performs blurriness and resolution checks on the input image."""
    results = {
        'is_blurry': False, 'blur_score': 0.0, 'is_low_res': False,
        'verdict': 'GOOD', 'details': []
    }

    try:
        img_stream = BytesIO(image_bytes)
        img_pil = Image.open(img_stream).convert("RGB")
        img_np = np.array(img_pil)

        # 1. Blurriness Check using Laplacian Variance
        gray = cv2.cvtColor(img_np, cv2.COLOR_RGB2GRAY)
        variance = cv2.Laplacian(gray, cv2.CV_64F).var()
        results['blur_score'] = variance

        if variance < BLUR_THRESHOLD:
            results['is_blurry'] = True
            results['details'].append(f"Image is blurry (Sharpness Score: {variance:.2f} < {BLUR_THRESHOLD:.2f}).")
            results['verdict'] = 'BAD'

        # 2. Resolution Check
        width, height = img_pil.size
        if width < MIN_DIM or height < MIN_DIM:
            results['is_low_res'] = True
            if results['verdict'] == 'GOOD':
                results['verdict'] = 'POOR'
            results['details'].append(
                f"Image resolution is low ({width}x{height} < {MIN_DIM}x{MIN_DIM}).")

        if not results['details']:
            results['details'].append("All quality checks passed.")

    except Exception as e:
        print(f"[ERROR] Image quality check failed: {e}")
        results['verdict'] = 'BAD'
        results['details'].append(f"Internal quality check error: {e}")

    return results


# ============================================================
# OCR EXECUTION
# ============================================================
def perform_ocr(image_bytes):
    """Performs OCR with EasyOCR, falls back to Tesseract if needed."""
    text = ""
    try:
        img_stream = BytesIO(image_bytes)
        img = Image.open(img_stream).convert("RGB")
        img = preprocess_image(img)

        if USE_EASYOCR:
            img_np = np.array(img)
            # Detail=0 returns simple list of strings, paragraph=True combines lines
            text_list = easyocr_reader_ta.readtext(img_np, detail=0, paragraph=True)
            text = " ".join(text_list)
        elif pytesseract:
            text = pytesseract.image_to_string(img, lang="eng+tam")
        else:
            print("[ERROR] No OCR engine available!")
            return ""
    except Exception as e:
        print("[ERROR] OCR failed:", e)
        return ""

    return clean_text(text)


# ============================================================
# TEXT CLEANING UTILITIES
# ============================================================
def clean_text(text):
    """Normalize and clean OCR output."""
    text = unicodedata.normalize("NFKD", text or "")
    # Replace newlines and colons with spaces for easier regex
    text = text.replace("\n", " ").replace(":", " ").replace("-", " ")
    # Keep alphanumeric, spaces, and forward slashes
    text = re.sub(r"[^A-Za-z0-9\s/]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def remove_known_junk(text):
    """Remove repetitive OCR noise or headers specific to ID cards."""
    junk = [
        "AADHAAR", "GOVERNMENT OF INDIA", "GOVT OF INDIA", "INCOME TAX DEPARTMENT",
        "PERMANENT ACCOUNT NUMBER CARD", "UNIQUE IDENTIFICATION AUTHORITY", "VID", "VIDE",
        "DRIVING LICENSE", "DRIVING LICENCE", "UNION OF INDIA",
        r"\bOFINDIA\b", r"\bO?F\s+INDIA\b", r"\bPEUA?NENT\b", r"\bACCAUN\b", 
        r"\bACCOUNT\b", r"\bPERMANENT\b", r"\bINDIA\b", r"\bNUMBER\b", r"\bCARD\b",
        r"\bNAME\b", r"\bNUAE\b", r"\bOF\s+NAME\b", r"\bNAUMAE\b", r"\bCARD\s+NUMBE?\b"
    ]
    for j in junk:
        text = re.sub(re.escape(j), " ", text, flags=re.IGNORECASE)
    return re.sub(r"\s+", " ", text).strip()


def clean_name(name):
    """Clean extracted name (remove prefixes, noise, isolated chars)."""
    # Remove common prefixes
    name = re.sub(r"\b(S/O|D/O|W/O|MR|MS|MRS|C/O|SRI|SHRI|HOLDER)\b", "", name, flags=re.IGNORECASE)
    # Allow only letters, spaces, and dots
    name = re.sub(r"[^A-Za-z\s\.]", " ", name)
    name = re.sub(r"\s+", " ", name).strip()
    # Remove trailing single initial (optional, depending on requirement)
    name = re.sub(r'\s+[A-Z]$', '', name, flags=re.IGNORECASE).strip() 
    # Remove residual noise words
    name = re.sub(r'\b(IT|HOLDER|HOLDERS|SIGNATURE)\b', '', name, flags=re.IGNORECASE).strip()
    name = re.sub(r'\s+', ' ', name).strip()
    return name


# ============================================================
# FUZZY NAME MATCHING & PRIORITY UTILS
# ============================================================
def fuzzy_match(a, b):
    """Compute fuzzy similarity score (0–100) between two strings."""
    if not a or not b: return 0
    return int(SequenceMatcher(None, a.lower(), b.lower()).ratio() * 100)


def override_name_if_similar(ocr_name, user_name_hint, threshold=75): 
    """
    Overrides OCR name if it's reasonably similar to user hint.
    This helps correct minor OCR typos using the user's provided name.
    """
    if not ocr_name or not user_name_hint: return ocr_name
    ocr_norm = clean_name(ocr_name).strip().upper()
    hint_norm = clean_name(user_name_hint).strip().upper()
    if not ocr_norm or not hint_norm: return ocr_name

    score = fuzzy_match(ocr_norm, hint_norm)
    if score >= threshold:
        print(f"[INFO] Name corrected: OCR '{ocr_name}' -> '{user_name_hint}' (Match {score}%)")
        return clean_name(user_name_hint).title()
    return ocr_name


def find_name_in_text(text, user_hint, threshold=80):
    """
    Strictly searches for the user_hint within the text.
    Returns the user_hint if found with high confidence.
    """
    if not user_hint or not text:
        return None
    
    clean_hint = clean_name(user_hint).strip().upper()
    clean_txt = re.sub(r"[^A-Z0-9\s]", " ", text.upper())
    
    if not clean_hint: return None

    # 1. Exact substring check (Strongest confirmation)
    if clean_hint in clean_txt:
        return clean_name(user_hint)

    # 2. Token-based fuzzy check for the first name
    hint_parts = clean_hint.split()
    if not hint_parts: return None
    
    first_name = hint_parts[0]
    if len(first_name) < 3: return None # Ignore very short names to avoid false positives

    text_words = clean_txt.split()
    for word in text_words:
        if fuzzy_match(first_name, word) >= threshold:
            # Found a word very similar to the first name of the hint
            return clean_name(user_hint)
            
    return None


# ============================================================
# AADHAAR DATA EXTRACTION
# ============================================================
def extract_aadhaar(raw_text, user_name_hint=None):
    data = {"name": "N/A", "dob": "N/A", "gender": "N/A", "id": "N/A"}
    if not raw_text: return data

    text = remove_known_junk(raw_text)
    text = unicodedata.normalize("NFKD", text)
    t = text.upper()

    # --- STRICT NAME PRIORITY ---
    # Check if user name exists in text BEFORE guessing
    strict_name = find_name_in_text(t, user_name_hint)
    if strict_name:
        data["name"] = strict_name.title()
    # ----------------------------

    # Step 2 — Extract Aadhaar ID, DOB, Gender
    # Aadhaar is 12 digits (4 4 4)
    uid = re.search(r"\b\d{4}\s?\d{4}\s?\d{4}\b", t)
    if uid: data["id"] = uid.group(0).replace(" ", "")

    # DOB Extraction
    dob = re.search(r"(?:DOB|DATE OF BIRTH|BIRTH)\s*[:\-\s]*([0-9]{2}[\/\-\s]?[0-9]{2}[\/\-\s]?[0-9]{4})", t)
    if not dob: dob = re.search(r"\b([0-9]{2}[\/\-\s]?[0-9]{2}[\/\-\s]?[0-9]{4})\b", t)
    if dob: data["dob"] = dob.group(1).replace(" ", "-").replace("/", "-")

    # Gender Extraction
    if "MALE" in t: data["gender"] = "MALE"
    elif "FEMALE" in t: data["gender"] = "FEMALE"
    elif "TRANSGENDER" in t: data["gender"] = "TRANSGENDER"

    # Step 3 — Heuristic Name Extraction (Only if strict check failed)
    if data["name"] == "N/A":
        parts = re.split(r"GOVERNMENT\s+OF\s+INDIA", t)
        candidate_zone = parts[1] if len(parts) > 1 else t
        # Restrict zone to before DOB/Gender
        candidate_zone = re.split(r"(?:DOB|BIRTH|MALE|FEMALE|TRANSGENDER)", candidate_zone)[0]
        
        # Remove common relation prefixes from the candidate zone
        candidate_zone = re.sub(r"\b(S\/O|D\/O|W\/O|MR|MS|MRS)\b", " ", candidate_zone)
        candidate_zone = re.sub(r"\s+", " ", candidate_zone).strip()

        # Find consecutive uppercase words
        candidates = re.findall(r"[A-Z]{2,}(?:\s+[A-Z\.]{1,}){0,3}", candidate_zone)
        best_ocr_candidate = "N/A"

        for c in candidates:
            if re.search(r"\d", c): continue # Skip if contains digits
            if re.search(r"[AEIOU]", c): # Must contain vowels
                clean = clean_name(c.title()) 
                if len(clean) > len(clean_name(best_ocr_candidate)):
                      best_ocr_candidate = clean

        if best_ocr_candidate != "N/A":
            data["name"] = override_name_if_similar(best_ocr_candidate, user_name_hint) 

    return data


# ============================================================
# NEW: AADHAAR BACK ADDRESS EXTRACTION
# ============================================================
def extract_aadhaar_back(raw_text):
    """
    Extracts address and pincode from the back side of an Aadhaar card.
    """
    data = {"address": "N/A", "pincode": "N/A"}
    if not raw_text: return data
    
    # Normalize text
    text = unicodedata.normalize("NFKD", raw_text)
    # Convert to upper but keep original structure roughly for regex
    text_upper = text.upper().replace("\n", " ").strip()
    
    # 1. Extract Pincode (Strong anchor)
    # Look for 6 digit number, often at the end or near State
    pin_match = re.search(r"\b(\d{6})\b", text_upper)
    if pin_match:
        data["pincode"] = pin_match.group(1)
        
    # 2. Extract Address Block
    # Strategy: 
    #   Start: "Address" keyword or "S/O", "W/O", "C/O"
    #   End: The Pincode or common footer words like "Download"
    
    start_match = re.search(r"(?:ADDRESS|ADDR)[:\s]*", text_upper)
    start_index = 0
    
    if start_match:
        start_index = start_match.end()
    else:
        # Fallback start: look for relationship markers
        rel_match = re.search(r"(?:S/O|W/O|D/O|C/O)", text_upper)
        if rel_match:
            start_index = rel_match.start()
            
    # Determine End Index
    end_index = len(text_upper)
    if pin_match:
        # Include pincode in the address string for validation context
        end_index = pin_match.end()
    
    # Extract raw chunk
    raw_address = text_upper[start_index:end_index].strip()
    
    # Cleanup junk from the start of the address string if it captured headers
    raw_address = re.sub(r"^(?:ADDRESS|ADDR)[:\-\s]*", "", raw_address)
    
    # Cleanup common noise
    noise_patterns = [
        r"UNIQUE IDENTIFICATION AUTHORITY OF INDIA",
        r"GOVERNMENT OF INDIA",
        r"ADDRESS",
        r"www\.uidai\.gov\.in",
        r"1947"
    ]
    for pat in noise_patterns:
        raw_address = re.sub(pat, " ", raw_address)
        
    # Final cleanup
    # Remove leading special chars
    raw_address = re.sub(r"^[^A-Z0-9]+", "", raw_address)
    raw_address = re.sub(r"\s+", " ", raw_address).strip()
    
    if len(raw_address) > 10:
        data["address"] = raw_address.title()
        
    return data


# ============================================================
# PAN DATA EXTRACTION
# ============================================================
def extract_pan_with_link(raw_text, aadhaar_name=None, user_name_hint=None):
    data = {"name": "N/A", "dob": "N/A", "gender": "N/A", "id": "N/A"}
    if not raw_text: return data

    clean_pan_text = remove_known_junk(raw_text).upper().replace("\n", " ")
    clean_pan_text = re.sub(r"[^A-Z0-9\s/]", " ", clean_pan_text)
    clean_pan_text = re.sub(r"\s+", " ", clean_pan_text).strip()

    # --- STRICT NAME PRIORITY ---
    # Prioritize user hint OR Aadhaar name
    context_name = aadhaar_name or user_name_hint
    strict_name = find_name_in_text(clean_pan_text, context_name)
    if strict_name: 
        data["name"] = strict_name.upper()
    # ----------------------------

    # Extract ID (Regex for PAN: 5 chars, 4 digits, 1 char)
    pan_match = re.search(r"\b[A-Z]{5}[A-Z0-9]{5}\b", clean_pan_text)
    if pan_match:
        pan_id_candidate = pan_match.group(0)
        # PAN Common OCR Misreads Correction
        correction_map = {'S': '5', 'O': '0', 'I': '1', 'L': '1', 'Z': '2', 'A': '4', 'G': '6'}
        corrected_id_parts = list(pan_id_candidate)
        
        # Correct only the 4 digit section (indices 5, 6, 7, 8)
        for i in range(5, 9): 
            char = corrected_id_parts[i]
            if char.isalpha() and char.upper() in correction_map:
                corrected_id_parts[i] = correction_map[char.upper()]
        corrected_id = "".join(corrected_id_parts)
        
        if re.fullmatch(r'[A-Z]{5}\d{4}[A-Z]{1}', corrected_id):
            data["id"] = corrected_id

    # DOB Extraction
    dob_match = re.search(r"\b\d{2}[\/\-\s]?\d{2}[\/\-\s]?\d{4}\b", clean_pan_text)
    if dob_match: data["dob"] = dob_match.group(0).replace(" ", "-").replace("/", "-")

    # Fallback Name Extraction (Only if strict check failed)
    if data["name"] == "N/A":
        search_zone = re.sub(r"[^A-Z\s]", " ", clean_pan_text)
        
        # Remove Father's Name label to avoid picking "Father" as name
        father_match = re.search(r"(?:FATHER|PITAH)\s+NAME\s+([A-Z\s]+)", search_zone)
        if father_match: 
            search_zone = search_zone.replace(father_match.group(0), " ")
        
        valid_name_parts = []
        junk = ["GOVT", "INDIA", "INCOME", "TAX", "DEPARTMENT", "SIGNATURE"]
        
        for word in search_zone.split():
            if word not in junk and len(word) > 2: 
                valid_name_parts.append(word)
        
        # Find the longest valid word sequence as the candidate name
        if valid_name_parts:
            best_name = max(valid_name_parts, key=len)
            final_pan_name = clean_name(best_name.upper()).upper()
            
            # Check if context name is similar to what we found
            if context_name:
                data["name"] = override_name_if_similar(final_pan_name, context_name).upper()
            else:
                data["name"] = final_pan_name

    return data


# ============================================================
# DRIVING LICENSE DATA EXTRACTION
# ============================================================
def extract_driving_license(raw_text, user_name_hint=None):
    data = {
        "id": "N/A", "name": "N/A", "father_name": "N/A",
        "dob": "N/A", "blood_group": "N/A",
        "issue_date": "N/A", "valid_till": "N/A", "address": "N/A"
    }
    if not raw_text: return data

    text = raw_text.upper()
    
    # --- PRE-CLEANING FOR STATE CODES ---
    # Fix common OCR errors for State Codes (especially TN for Tamil Nadu)
    # 1N -> TN, 7N -> TN, IN0 -> TN0, etc.
    corrections = {
        r"\b1N": "TN", r"\b7N": "TN", r"\bIN0": "TN0", 
        r"\bDL\s?N0": "DL NO", r"\bLICENCE\s?N0": "DL NO",
        r"1NDIA": "INDIA",
        # Fix space insertion in ID: "TN 07" -> "TN07"
        r"([A-Z]{2})\s+([0-9]{2})": r"\1\2"
    }
    for pat, repl in corrections.items():
        text = re.sub(pat, repl, text)

    text = remove_known_junk(text)
    text = re.sub(r"[\n:]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()

    # --- STRICT NAME PRIORITY ---
    strict_name = find_name_in_text(text, user_name_hint)
    if strict_name: 
        data["name"] = strict_name.title()
    # ----------------------------

    # --- ID EXTRACTION LOGIC ---
    # 1. Look for "DL NO" followed by ID
    dl_label_pattern = r"(?:DL\s*NO|LICENCE\s*NO)\s*[:\-\s]*([A-Z0-9\s\-]{10,25})"
    m_label = re.search(dl_label_pattern, text)

    # 2. Look for Standard Pattern (SS-RR-YYYY-NNNNNNN)
    # Matches: TN01 2020 1234567 or similar variations
    std_pattern = r"\b([A-Z]{2}[0-9]{2,3})[\s\-]?([0-9]{4})[\s\-]?([0-9]{5,7})\b"
    m_std = re.search(std_pattern, text)

    raw_id = None

    if m_label:
        raw_id = m_label.group(1)
    elif m_std:
        raw_id = m_std.group(0)
    else:
        # 3. Fallback: Long alphanumeric string
        candidates = re.findall(r"\b[A-Z0-9]{10,20}\b", text)
        # Filter: Must have at least 4 digits and length > 10
        valid = [c for c in candidates if sum(c.isdigit() for c in c) > 4 and len(c) > 10]
        if valid: raw_id = max(valid, key=len)

    if raw_id:
        # Clean the ID
        clean_id = re.sub(r'\W+', '', raw_id)
        
        # --- CRITICAL FIXES ---
        
        # Case 1: ID starts with digit (1 or 7), long length, missing State Code
        if clean_id[0].isdigit() and len(clean_id) >= 15:
            
            # Specific fix for "1917...NT..." pattern (User Request)
            # Input: 191720210002367NT900D -> Desired: TN191720210002367
            # We detect "19" start, long length. We grab the 15 digits starting at 19 and prefix TN.
            if clean_id.startswith("19"):
                # Regex to capture 15 digits starting with 19
                # This ignores the trailing noise like "NT900D"
                match_clean = re.match(r"(19\d{13})", clean_id)
                if match_clean:
                    clean_id = "TN" + match_clean.group(1)
            
            # Case 2: Generic scan for missing State Code if not handled above
            # Re-scan for State Code pattern specifically in the text
            elif not clean_id.startswith("TN"):
                scan_state = re.search(r"\b([A-Z]{2})[\s\-]?" + re.escape(clean_id), text.replace(" ", ""))
                if scan_state:
                    clean_id = scan_state.group(1) + clean_id
                elif clean_id.startswith('1N'):
                    clean_id = 'TN' + clean_id[2:]

        data["id"] = clean_id

    # --- NAME & DETAILS EXTRACTION ---
    if data["name"] == "N/A":
        extracted_name = "N/A"
        name_block = re.search(r"(?:NAME|HOLDER|HOLDERS|SIGNATURE|SIG)\s*[:\-]?\s*([A-Z\s]{3,60})", text)
        dob_anchor = re.search(r"(DOB|DATE OF BIRTH)", text)

        if not name_block and dob_anchor:
            # Look for name above DOB
            top_area = text[:dob_anchor.start()]
            possible_names = re.findall(r"[A-Z]{3,}(?:\s+[A-Z]{2,}){0,4}", top_area)
            if possible_names: 
                extracted_name = clean_name(max(possible_names, key=len).title())
        if name_block:
            block = name_block.group(1)
            block = re.sub(r'\b(HOLDER|SIGNATURE|DRIVING|LICENCE|NAME)\b', ' ', block)
            # Stop at labels
            extracted_name = re.split(r"(BLOOD|DOB|DATE)", block)[0].strip()

        extracted_name = re.sub(r"^(IT|IL|LT)\s+", "", extracted_name)
        if extracted_name != "N/A":
             data["name"] = override_name_if_similar(extracted_name, user_name_hint)

    # Dates
    date_pattern = r'(\d{2}[-/\s]?\d{2}[-/\s]?\d{4})'
    dob_match = re.search(r"(?:DOB|DATE OF BIRTH)\s*" + date_pattern, text)
    if dob_match: data["dob"] = dob_match.group(1).replace(" ", "-").replace("/", "-")
    
    issue = re.search(r"(?:ISSUE DATE|ISSUED ON|ISSUE)\s*" + date_pattern, text)
    if issue: data["issue_date"] = issue.group(1).replace(" ", "-").replace("/", "-")
    
    valid = re.search(r"(?:VALIDITY|VALID TILL)\s*" + date_pattern, text)
    if valid: data["valid_till"] = valid.group(1).replace(" ", "-").replace("/", "-")

    # Father's Name
    father = re.search(r"(?:S/O|D/O|W/O|SON OF)\s*([A-Z\s]{3,80}?)(?:ADDRESS|DOB|$)", text)
    if father: data["father_name"] = clean_name(father.group(1).title())

    # Blood Group
    bg = re.search(r"BLOOD\s*GROUP\s*([AOB][\+\-]?)", text)
    if bg: data["blood_group"] = bg.group(1).upper()

    # Address
    addr = re.search(r"(?:ADDRESS|ADDR)\s*([A-Z0-9\s,/.]{10,300}?)(?:\b\d{6}|ISSUE|VALID|$)", text)
    if addr: data["address"] = addr.group(1).strip().title()

    return data


# ============================================================
# UTILITY BILL EXTRACTION
# ============================================================
def extract_utility_bill(raw_text, user_name_hint=None):
    """
    Extracts information from Electricity / Gas / Phone bills.
    Supports DALL-E generated electricity bills and real Indian formats.
    """
    data = {
        "id": "N/A",
        "name": "N/A",
        "bill_date": "N/A",
        "amount": "N/A",
        "provider": "Electricity Board",
        "address": "N/A"
    }

    if not raw_text:
        return data

    text = raw_text.upper()
    text = re.sub(r"[\n:]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()

    # ----------------------------------------
    # 1️⃣  Provider
    # ----------------------------------------
    providers = ["TNEB", "TANGEDCO", "BESCOM", "ADANI", "TATA POWER",
                 "BSES", "MAHAVITARAN", "IGL", "MGL", "AIRTEL", "JIO", "BSNL"]
    for p in providers:
        if p in text:
            data["provider"] = p
            break

    # ----------------------------------------
    # 2️⃣ Consumer Number (your generated bill uses "Consumer Number")
    # ----------------------------------------
    cid = re.search(r"(CONSUMER NUMBER|CONSUMER NO|CONSUMER ID)\s*([A-Z0-9\-]{4,20})", text)
    if cid:
        data["id"] = cid.group(2).replace(" ", "")
    else:
        fallback = re.search(r"\b\d{6,12}\b", text)
        if fallback:
            data["id"] = fallback.group(0)

    # ----------------------------------------
    # 3️⃣ Billing Period / Bill Date
    # ----------------------------------------
    bp = re.search(r"BILLING PERIOD\s*(\d{2}[-/]\d{2}[-/]\d{4})", text)
    if bp:
        data["bill_date"] = bp.group(1)
    else:
        dt = re.search(r"\b\d{2}[-/]\d{2}[-/]\d{4}\b", text)
        if dt:
            data["bill_date"] = dt.group(0)

    # ----------------------------------------
    # 4️⃣ Amount Due (matches DALL-E format)
    # ----------------------------------------
    amt = re.search(r"(AMOUNT DUE|TOTAL|PAYABLE)\s*[₹RS\. ]*\s*([\d,]+)", text)
    if amt:
        data["amount"] = amt.group(2).replace(",", "")

    # ----------------------------------------
    # 5️⃣ NAME (strict user hint or label)
    # ----------------------------------------
    strict_name = find_name_in_text(text, user_name_hint)
    if strict_name:
        data["name"] = strict_name.title()
    else:
        nm = re.search(r"(NAME|CUSTOMER)\s*([A-Z\s]{3,40})", text)
        if nm:
            data["name"] = clean_name(nm.group(2)).title()

    # ----------------------------------------
    # 6️⃣ ADDRESS — WORKS FOR YOUR BILL FORMAT
    # ----------------------------------------
    # Extract everything between "CONSUMER NAME" and "CONSUMER NUMBER"
    addr_block = re.search(
        r"CONSUMER NAME.*?(CONSUMER NUMBER|BILL NUMBER)",
        text,
        re.DOTALL
    )

    # FALLBACK: If block method fails, look for Pincode explicitly and grab context
    if not addr_block:
        # Find a Pincode (6 digits)
        pin_search = re.search(r"\b\d{6}\b", text)
        if pin_search:
            # Grab 100 chars before the pincode
            start_idx = max(0, pin_search.start() - 100)
            end_idx = pin_search.end()
            raw_addr = text[start_idx:end_idx]
            # Clean up: remove common headers found in that range
            raw_addr = re.sub(r"(NAME|DATE|BILL).*", "", raw_addr) 
            data["address"] = raw_addr.strip().title()

    elif addr_block:
        block = addr_block.group(0)

        # remove name from block
        block = re.sub(r"CONSUMER NAME\s+[A-Z\s]+", "", block)

        # extract address-like text (words, numbers, commas, slashes)
        # CHANGED: explicitly allow 6-digit patterns to ensure PIN isn't filtered out
        addr_lines = re.findall(r"[A-Z0-9\s,/-]{5,}", block)

        cleaned = []
        for line in addr_lines:
            line = line.strip()
            if len(line) >= 5 and not line.startswith("CONSUMER"):
                cleaned.append(line.title())

        if cleaned:
            data["address"] = " ".join(cleaned)

    return data