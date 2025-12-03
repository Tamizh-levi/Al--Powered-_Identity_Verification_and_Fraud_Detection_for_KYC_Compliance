import os
from face_matcher import FaceMatcher 

# --- Directory Configuration ---
UPLOAD_FOLDER = 'static/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- Database Configuration ---
db_config = {
    "host": "localhost",
    "user": "root",
    "password": "s.tamizh@2005",
    "database": "smart_kyc",
    "auth_plugin": "mysql_native_password"
}

# --- Service Initialization ---
# Initialize Face Matcher (Conceptual)
face_matcher = FaceMatcher()
# Expose the instance and folder for use in routes
LIVE_PHOTO_FOLDER = face_matcher.live_folder
FACE_MATCHER_SERVICE = face_matcher

# --- Admin Credentials (for simulation) ---
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin123'