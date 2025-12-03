import os
from flask import Flask, jsonify, send_file
from flask_cors import CORS

# Import configurations and modules
from config import UPLOAD_FOLDER
from db import get_db
from user_routes import user_bp
from admin_routes import admin_bp

# Initialize the Flask application
app = Flask(__name__)
CORS(app) # Enable CORS
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Register Blueprints
app.register_blueprint(user_bp)
app.register_blueprint(admin_bp)

# --- General Routes (Root/Health) ---

@app.route('/api/health', methods=['GET'])
def api_health():
    """Health check endpoint."""
    return jsonify({"status":"ok","service":"smartkyc-backend"}), 200

# Small utility: serve uploaded file (if not handled by admin_routes)
@app.route('/uploads/<path:filename>', methods=['GET'])
def serve_upload_general(filename):
    """Serves uploaded files from the static/uploads folder."""
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(path):
        # Using send_file without a blueprint path is slightly cleaner here
        return send_file(path)
    return jsonify({"status":"error","message":"File not found"}), 404

# --- Runner ---
if __name__ == '__main__':
    # Add a simple check for database connection on startup (optional)
    if get_db():
        print("Database connection verified on startup.")
    else:
        print("WARNING: Database connection failed on startup.")
        
    app.run(debug=True, host='0.0.0.0', port=5000)