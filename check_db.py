from infrastrucutre.database import engine
from sqlalchemy import text

def check_database():
    """Check the structure and content of the endpoints table"""
    with engine.connect() as conn:
        # Get table info
        table_info = conn.execute(text("PRAGMA table_info(endpoints)")).fetchall()
        print("\nEndpoints table structure:")
        for col in table_info:
            print(f"Column: {col[1]}, Type: {col[2]}, NotNull: {col[3]}, DefaultVal: {col[4]}")
        
        # Get sample data if any exists
        print("\nSample endpoints (if any):")
        sample = conn.execute(text("""
            SELECT id, full_url, domain, path_segments, endpoint_type, resource_id, 
                   source_page, discovery_tag, discovery_attribute
            FROM endpoints
            LIMIT 3
        """)).fetchall()
        
        for row in sample:
            print(f"\nEndpoint {row[0]}:")
            print(f"  Full URL: {row[1]}")
            print(f"  Domain: {row[2]}")
            print(f"  Path Segments: {row[3]}")
            print(f"  Type: {row[4]}")
            print(f"  Resource ID: {row[5]}")
            print(f"  Source Page: {row[6]}")
            print(f"  Discovery Tag: {row[7]}")
            print(f"  Discovery Attribute: {row[8]}")

if __name__ == '__main__':
    check_database()
