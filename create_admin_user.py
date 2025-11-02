"""Script to create or update admin user in database."""
import asyncio
import sys
from storage.database import DatabaseManager

async def create_admin_user():
    """Create or update admin user."""
    db_manager = DatabaseManager()
    await db_manager.initialize()
    
    username = "admin"
    password = "admin123"
    
    print(f"Creating admin user...")
    print(f"Username: {username}")
    print(f"Password: {password}")
    print(f"Using plain text password (for development)")
    
    # Insert or replace user
    import aiosqlite
    async with aiosqlite.connect(db_manager.db_path) as db:
        # First, delete existing user if exists
        await db.execute("DELETE FROM admin_users WHERE username = ?", (username,))
        
        # Insert new user with plain text password
        await db.execute("""
            INSERT INTO admin_users (username, password_hash)
            VALUES (?, ?)
        """, (username, password))
        await db.commit()
        
        print(f"\n✓ Admin user '{username}' created/updated successfully!")
        print(f"\nYou can now login with:")
        print(f"  Username: {username}")
        print(f"  Password: {password}")

if __name__ == "__main__":
    try:
        asyncio.run(create_admin_user())
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

