import mysql.connector
from flask import current_app

# The config module should be imported where db_config is needed. 
# Since config.py is defined in the same package, we'll assume access to its variables.
from config import db_config

def get_db():
    """Establishes and returns a database connection."""
    try:
        # Use current_app.logger for logging errors in Flask context
        return mysql.connector.connect(**db_config)
    except Exception as e:
        # Use a print statement for standalone testing, or Flask's logger in context
        print(f"DB connection error: {e}")
        return None