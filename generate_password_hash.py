"""Utility script to generate password hash for admin user."""
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

if __name__ == "__main__":
    password = input("Enter password to hash: ")
    hashed = pwd_context.hash(password)
    print(f"\nHashed password: {hashed}")
    print(f"\nTo use this in the database, update admin_users table with:")
    print(f"UPDATE admin_users SET password_hash = '{hashed}' WHERE username = 'admin';")

