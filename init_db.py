from app import app, db, User
import bcrypt
from datetime import datetime
import os

def init_database():
    with app.app_context():
        # Drop all tables and recreate them
        db.drop_all()
        db.create_all()
        
        # Create test user
        hashed_password = bcrypt.hashpw('password123'.encode('utf-8'), bcrypt.gensalt())
        test_user = User(
            username='admin',
            password=hashed_password,
            last_password_change=datetime.utcnow()
        )
        db.session.add(test_user)
        db.session.commit()
        print("Test user created - Username: admin, Password: password123")

if __name__ == '__main__':
    # Delete the database file if it exists
    if os.path.exists('brute_force_sim.db'):
        os.remove('brute_force_sim.db')
        print("Removed old database")
    
    init_database() 