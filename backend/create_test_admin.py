import sys
import uuid
from sqlalchemy.orm import Session
from database import SessionLocal
from models import User, UserRole
from auth import hash_password
from datetime import datetime, timezone


def create_test_admin():
    print("Creating test admin user...")
    
    db: Session = SessionLocal()
    
    try:
        existing_user = db.query(User).filter(User.username == "admin").first()
        if existing_user:
            print("Admin user already exists!")
            print("Username: admin")
            print("Password: admin123")
            return True
        
        admin_user = User(
            id=uuid.uuid4(),
            username="admin",
            email="admin@spectre.local",
            full_name="System Administrator",
            hashed_password=hash_password("admin123"),
            role=UserRole.ADMIN,
            is_active=True,
            created_at=datetime.now(timezone.utc)
        )
        
        db.add(admin_user)
        db.commit()
        
        print("=====================================")
        print("Admin user created successfully!")
        print("=====================================")
        print("Username: admin")
        print("Password: admin123")
        print("Email: admin@spectre.local")
        print("Role: ADMIN")
        print("=====================================")
        print("You can now login at http://localhost:3000")
        print("=====================================")
        
        return True
        
    except Exception as e:
        db.rollback()
        print(f"Error creating admin user: {e}")
        return False
    finally:
        db.close()


if __name__ == "__main__":
    try:
        success = create_test_admin()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)
