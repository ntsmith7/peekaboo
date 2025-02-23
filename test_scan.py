import asyncio
from infrastrucutre.database import DatabaseSession
from crawling import service
from core.models import Subdomain

async def test_scan():
    """Run a test scan on a single subdomain"""
    session = DatabaseSession()
    
    try:
        # Create a test subdomain
        subdomain = Subdomain(
            domain="www.coolblue.nl",
            is_alive=True,
            source=None,  # Optional field
            ip_addresses=[],  # Empty list for now
            http_status=None,  # Will be updated during scan
            is_takeover_candidate=False,
            additional_info={}
        )
        
        try:
            session.add(subdomain)
            session.commit()
            print(f"Created test subdomain with ID: {subdomain.id}")
        except Exception as e:
            print(f"Error creating subdomain: {str(e)}")
            session.rollback()
            raise
        
        # Run the crawler
        try:
            async with service.CrawlingService(session) as crawler:
                print("\nStarting test crawl...")
                await crawler.crawl_specific_targets([subdomain.id])
        except Exception as e:
            print(f"Error during crawl: {str(e)}")
            raise
        
        # Check results
        try:
            print("\nCrawl complete. Checking results...")
            subdomain_with_endpoints = session.query(Subdomain).get(subdomain.id)
            if not subdomain_with_endpoints:
                print("Error: Subdomain not found after crawl")
                return
                
            endpoints = subdomain_with_endpoints.endpoints
            
            if endpoints:
                print(f"\nFound {len(endpoints)} endpoints. Sample:")
                for endpoint in endpoints[:3]:
                    print(f"\nEndpoint: {endpoint.full_url}")
                    print(f"Type: {endpoint.endpoint_type}")
                    print(f"Resource ID: {endpoint.resource_id}")
                    print(f"Source: {endpoint.source_page}")
                    print(f"Discovery: {endpoint.discovery_tag} [{endpoint.discovery_attribute}]")
                    print(f"Status Code: {endpoint.status_code}")
                    print(f"Content Type: {endpoint.content_type}")
            else:
                print("No endpoints found")
                
        except Exception as e:
            print(f"Error checking results: {str(e)}")
            raise
            
    except Exception as e:
        print(f"Test scan failed: {str(e)}")
        raise
    finally:
        session.close()

if __name__ == '__main__':
    asyncio.run(test_scan())
