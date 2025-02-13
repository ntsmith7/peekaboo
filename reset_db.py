import os
from infrastrucutre.database import engine
from core.models import Base

def reset_database():
    """Reset the database by dropping and recreating all tables"""
    # Remove existing database file
    try:
        os.remove('subdomains.db')
        print("Removed existing database file")
    except FileNotFoundError:
        print("No existing database file found")
    
    # Create new tables
    Base.metadata.create_all(engine)
    print("Created new database tables")

if __name__ == '__main__':
    reset_database()
