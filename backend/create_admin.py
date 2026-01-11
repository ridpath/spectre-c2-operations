import sys
import uuid
from getpass import getpass
from sqlalchemy.orm import Session
from database import SessionLocal, init_db
from models import User, UserRole
from auth import hash_password
from datetime import datetime, timezone


def create_admin_user():
    print("=" * 70)
    print("Spectre C2 - Admin User Creation")
    print("=" * 70)
    print()
    
    db: Session = SessionLocal()
    
    try:
        username = input("Enter admin username: ").strip()
        if not username:
            print("Error: Username cannot be empty")
            return False
        
        existing_user = db.query(User).filter(User.username == username).first()
        if existing_user:
            print(f"Error: User '{username}' already exists")
            return False
        
        email = input("Enter admin email: ").strip()
        if not email or "@" not in email:
            print("Error: Invalid email address")
            return False
        
        existing_email = db.query(User).filter(User.email == email).first()
        if existing_email:
            print(f"Error: Email '{email}' already in use")
            return False
        
        full_name = input("Enter full name (optional): ").strip() or None
        
        password = getpass("Enter password: ")
        password_confirm = getpass("Confirm password: ")
        
        if password != password_confirm:
            print("Error: Passwords do not match")
            return False
        
        if len(password) < 8:
            print("Error: Password must be at least 8 characters long")
            return False
        
        print()
        print("Creating admin user...")
        
        admin_user = User(
            id=uuid.uuid4(),
            username=username,
            email=email,
            full_name=full_name,
            hashed_password=hash_password(password),
            role=UserRole.ADMIN,
            is_active=True,
            created_at=datetime.now(timezone.utc)
        )
        
        db.add(admin_user)
        db.commit()
        
        print()
        print("=" * 70)
        print("✓ Admin user created successfully!")
        print("=" * 70)
        print(f"Username: {username}")
        print(f"Email: {email}")
        print(f"Role: ADMIN")
        print(f"User ID: {admin_user.id}")
        print("=" * 70)
        print()
        
        return True
        
    except Exception as e:
        db.rollback()
        print(f"Error creating admin user: {e}")
        return False
    finally:
        db.close()


if __name__ == "__main__":
    try:
        init_db()
        success = create_admin_user()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nFatal error: {e}")
        sys.exit(1)
