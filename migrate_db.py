from app import app, db
from datetime import datetime
from sqlalchemy import text

def upgrade_database():
    with app.app_context():
        try:
            # Add columns one by one for SQLite compatibility
            with db.engine.connect() as conn:
                # Add password column
                conn.execute(text("ALTER TABLE login_attempt ADD COLUMN password TEXT"))
                # Add headers column
                conn.execute(text("ALTER TABLE login_attempt ADD COLUMN headers TEXT"))
                # Add cookies column
                conn.execute(text("ALTER TABLE login_attempt ADD COLUMN cookies TEXT"))
                # Add geo_location column
                conn.execute(text("ALTER TABLE login_attempt ADD COLUMN geo_location TEXT"))
                # Add attack_type column
                conn.execute(text("ALTER TABLE login_attempt ADD COLUMN attack_type VARCHAR(50)"))
                conn.commit()
            print("Database upgraded successfully!")
        except Exception as e:
            print(f"Error upgrading database: {e}")
            print("If the columns already exist, you can ignore this error.")
            pass

if __name__ == '__main__':
    upgrade_database() 