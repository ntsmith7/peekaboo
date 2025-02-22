"""
This module is deprecated. Use the new service-based implementation:

from discovery import create_discovery_service

Example usage:
    service = await create_discovery_service(db_session, subdomain_model)
    results = await service.discover(target)
"""

import warnings
from typing import List, Dict, Any
from infrastructure.logging_config import get_logger
from . import create_discovery_service

class SubdomainDiscovery:
    """Legacy class maintained for backward compatibility"""
    
    def __init__(self, target: str, db_session, subdomain_model, clean_target_url_func, rate_limit: int = 5):
        warnings.warn(
            "SubdomainDiscovery class is deprecated. Use create_discovery_service() instead.",
            DeprecationWarning,
            stacklevel=2
        )
        self.target = clean_target_url_func(target)
        self.db_session = db_session
        self.subdomain_model = subdomain_model
        self.rate_limit = rate_limit
        self._service = None
        self.logger = get_logger(__name__)

    async def __aenter__(self):
        """Set up resources when entering context"""
        self._service = await create_discovery_service(
            db_session=self.db_session,
            subdomain_model=self.subdomain_model,
            rate_limit=self.rate_limit
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Clean up resources when exiting context"""
        if self._service:
            await self._service.network.cleanup()

    async def discover(self, include_bruteforce: bool = False) -> List[Dict[str, Any]]:
        """Legacy discover method that uses the new service internally"""
        if not self._service:
            self._service = await create_discovery_service(
                db_session=self.db_session,
                subdomain_model=self.subdomain_model,
                rate_limit=self.rate_limit
            )
        
        try:
            return await self._service.discover(self.target, include_bruteforce)
        except Exception as e:
            self.logger.error(f"Discovery failed: {str(e)}", exc_info=True)
            raise
