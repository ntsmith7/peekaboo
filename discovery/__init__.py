from typing import Optional
from infrastructure.database import DatabaseSession
from .service import SubdomainDiscoveryService
from .network import NetworkOperations
from .scanner import SubdomainScanner
from .repository import SubdomainRepository

async def create_discovery_service(
    db_session: DatabaseSession,
    subdomain_model,
    rate_limit: int = 5,
    network_timeout: int = 30
) -> SubdomainDiscoveryService:
    """
    Create and initialize a configured SubdomainDiscoveryService.
    
    Args:
        db_session: Database session for persistence
        subdomain_model: The model class for subdomain records
        rate_limit: Rate limit for scanning operations
        network_timeout: Timeout for network operations in seconds
        
    Returns:
        Configured SubdomainDiscoveryService instance
    """
    # Initialize components
    network = NetworkOperations(timeout=network_timeout)
    scanner = SubdomainScanner(rate_limit=rate_limit)
    repository = SubdomainRepository(db_session, subdomain_model)
    
    # Setup network operations
    await network.setup()
    
    # Create service
    service = SubdomainDiscoveryService(
        network_ops=network,
        scanner=scanner,
        repository=repository
    )
    
    return service

__all__ = [
    'create_discovery_service',
    'SubdomainDiscoveryService',
    'NetworkOperations',
    'SubdomainScanner',
    'SubdomainRepository'
]
