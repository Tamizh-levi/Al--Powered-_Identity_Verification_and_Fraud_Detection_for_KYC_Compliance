from db import get_db

def check_multiple_uploads_same_device(device_hash):
    """
    Rule 1: HIGH RISK — same device uploads >=3 documents in last 10 mins.
    """
    db = get_db()
    if not db: 
        return False

    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT COUNT(*) AS cnt 
            FROM device_logs 
            WHERE device_hash = %s 
              AND timestamp >= NOW() - INTERVAL 10 MINUTE
        """, (device_hash,))
        
        row = cursor.fetchone()
        return row["cnt"] >= 3

    except Exception as e:
        print(f"[Fraud Check Error] check_multiple_uploads: {e}")
        return False
    finally:
        cursor.close()


def check_multiple_devices_same_user(user_id):
    """
    Rule 2: MEDIUM RISK — user has >=3 different devices in last 15 mins.
    """
    db = get_db()
    if not db: 
        return False

    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT COUNT(DISTINCT device_hash) AS cnt
            FROM device_logs
            WHERE user_id = %s 
              AND timestamp >= NOW() - INTERVAL 15 MINUTE
        """, (user_id,))
        
        row = cursor.fetchone()
        return row["cnt"] >= 3

    except Exception as e:
        print(f"[Fraud Check Error] check_multiple_devices: {e}")
        return False
    finally:
        cursor.close()


def get_user_device_risk_report(user_id):
    """
    Returns a detailed risk report for frontend Fraud Page.
    """
    db = get_db()
    if not db:
        return {"risk_flags": [], "score": 0, "level": "LOW", "reason": "DB unavailable"}

    cursor = db.cursor(dictionary=True)
    risk_flags = []
    risk_score = 0

    try:
        # RULE 2: MULTIPLE DEVICES
        if check_multiple_devices_same_user(user_id):
            risk_flags.append("User used multiple devices (>3) within last 15 minutes")
            risk_score += 40

        # Fetch the user's devices safely
        cursor.execute("""
            SELECT device_hash, MAX(timestamp) AS last_seen
            FROM device_logs 
            WHERE user_id = %s
            GROUP BY device_hash
            ORDER BY last_seen DESC
            LIMIT 5
        """, (user_id,))
        
        devices = cursor.fetchall()

        # RULE 1: DEVICE HIGH UPLOAD VOLUME
        for dev in devices:
            if check_multiple_uploads_same_device(dev["device_hash"]):
                risk_flags.append("A device used by this user uploaded too many documents (>3 in 10 min)")
                risk_score += 50
                break

        # --- FINAL SCORE LOGIC ---
        if risk_score >= 70:
            level = "HIGH"
        elif risk_score >= 30:
            level = "MEDIUM"
        else:
            level = "LOW"

        return {
            "risk_flags": risk_flags,
            "score": risk_score,
            "level": level,
            "reason": " | ".join(risk_flags) if risk_flags else "No suspicious behaviour detected",
            "device_count": len(devices),
            "devices": devices
        }

    except Exception as e:
        return {
            "risk_flags": [f"Error running fraud checks: {str(e)}"],
            "score": 0,
            "level": "ERROR"
        }

    finally:
        cursor.close()
