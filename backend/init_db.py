import sys
from database import engine, Base, SessionLocal
from models import User, UserRole
from auth import hash_password
from config import get_settings
import uuid

settings = get_settings()


def init_database():
    print("Creating all database tables...")
    Base.metadata.create_all(bind=engine)
    print("Database tables created successfully!")
    
    db = SessionLocal()
    try:
        existing_admin = db.query(User).filter(User.username == "admin").first()
        if not existing_admin:
            print("\nCreating default admin user...")
            admin_user = User(
                id=uuid.uuid4(),
                username="admin",
                email="admin@spectre.local",
                hashed_password=hash_password("admin123"),
                full_name="System Administrator",
                role=UserRole.ADMIN,
                is_active=True
            )
            db.add(admin_user)
            db.commit()
            print("Default admin user created!")
            print("  Username: admin")
            print("  Password: admin123")
            print("  Role: admin")
            print("\n[WARNING] IMPORTANT: Change the admin password immediately in production!")
        else:
            print("\nAdmin user already exists. Skipping creation.")
        
        print("\n[SUCCESS] Database initialization complete!")
        
    except Exception as e:
        print(f"\n[ERROR] Error during initialization: {e}")
        db.rollback()
        sys.exit(1)
    finally:
        db.close()


if __name__ == "__main__":
    try:
        init_database()
    except Exception as e:
        print(f"\n✗ Fatal error: {e}")
        sys.exit(1)
