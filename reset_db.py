import os
from infrastrucutre.database import engine
from core.models import Base
from sqlalchemy import text

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
    
    # Add new columns to endpoints table
    with engine.connect() as conn:
        try:
            # Add URL component columns
            conn.execute(text("""
                ALTER TABLE endpoints 
                ADD COLUMN full_url TEXT NOT NULL DEFAULT '';
            """))
            conn.execute(text("""
                ALTER TABLE endpoints 
                ADD COLUMN domain TEXT NOT NULL DEFAULT '';
            """))
            conn.execute(text("""
                ALTER TABLE endpoints 
                ADD COLUMN path_segments TEXT DEFAULT '[]';
            """))
            conn.execute(text("""
                ALTER TABLE endpoints 
                ADD COLUMN endpoint_type TEXT;
            """))
            conn.execute(text("""
                ALTER TABLE endpoints 
                ADD COLUMN resource_id TEXT;
            """))
            
            # Add discovery context columns
            conn.execute(text("""
                ALTER TABLE endpoints 
                ADD COLUMN source_page TEXT;
            """))
            conn.execute(text("""
                ALTER TABLE endpoints 
                ADD COLUMN discovery_tag TEXT;
            """))
            conn.execute(text("""
                ALTER TABLE endpoints 
                ADD COLUMN discovery_attribute TEXT;
            """))
            
            # Update existing rows
            conn.execute(text("""
                UPDATE endpoints 
                SET full_url = path,
                    domain = CASE 
                        WHEN instr(path, '//') > 0 
                        THEN substr(
                            path,
                            instr(path, '//') + 2,
                            CASE 
                                WHEN instr(substr(path, instr(path, '//') + 2), '/') = 0 
                                THEN length(path)
                                ELSE instr(substr(path, instr(path, '//') + 2), '/') - 1
                            END
                        )
                        ELSE ''
                    END
                WHERE path LIKE 'http%';
            """))
            
            conn.commit()
            print("Added new columns to endpoints table")
            
        except Exception as e:
            print(f"Note: {str(e)}")
            # If columns already exist, that's fine
            pass

    print("\nDatabase reset complete!")

if __name__ == '__main__':
    reset_database()
