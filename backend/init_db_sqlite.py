#!/usr/bin/env python3
import os
import sys
import uuid
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from models import Base, User, UserRole
from auth import hash_password

# Force SQLite database
DATABASE_URL = "sqlite:///./spectre_c2.db"

print(f"Initializing database at: {DATABASE_URL}")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

# Drop all tables and recreate
print("Dropping existing tables...")
Base.metadata.drop_all(bind=engine)

print("Creating all tables...")
Base.metadata.create_all(bind=engine)

# Create admin user
print("Creating admin user...")
db = Session(engine)

try:
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
    
    print("=" * 70)
    print("SUCCESS: Database initialized successfully!")
    print("=" * 70)
    print("Admin user created:")
    print(f"  Username: admin")
    print(f"  Password: admin123")
    print(f"  Email: admin@spectre.local")
    print(f"  Role: ADMIN")
    print(f"  User ID: {admin_user.id}")
    print("=" * 70)
    
except Exception as e:
    db.rollback()
    print(f"Error: {e}")
    sys.exit(1)
finally:
    db.close()
