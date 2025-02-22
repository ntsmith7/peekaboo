import asyncio
from datetime import datetime
from typing import List, Dict, Any, Set
from infrastructure.logging_config import get_logger
from .network import NetworkOperations
from .scanner import SubdomainScanner
from .repository import SubdomainRepository

__all__ = ['SubdomainDiscoveryService']

class SubdomainDiscoveryService:
    """
    Core service that manages subdomain discovery process. Coordinates discovery,
    validation and storage of subdomains while delegating actual network/scanning operations.
    """
    def __init__(self, 
                 network_ops: NetworkOperations,    # Handles DNS, HTTP, takeover checks
                 scanner: SubdomainScanner,         # Handles passive subdomain discovery
                 repository: SubdomainRepository):   # Handles data storage
        self.network = network_ops
        self.scanner = scanner  
        self.repository = repository
        self.logger = get_logger(__name__)
        
        # Track discovery progress
        self.discovered: Set[str] = set()
        self.results: List[Dict[str, Any]] = []

    async def discover(self, target: str, include_bruteforce: bool = False) -> List[Dict[str, Any]]:
        """Main method to run the subdomain discovery process"""
        start_time = datetime.utcnow()
        self.logger.info(f"Starting discovery for {target}")
        
        # Reset state for new discovery
        self.discovered.clear()
        self.results.clear()
        
        try:
            # Check base domain first
            await self._process_subdomain(target, "BASE")
            
            # Run passive scanning
            discovered = await self.scanner.scan(target)
            
            # Process discovered domains concurrently
            tasks = [
                self._process_subdomain(domain, "PASSIVE")
                for domain in discovered
                if domain not in self.discovered  # Skip already processed
            ]
            
            if tasks:
                await asyncio.gather(*tasks)
            
            duration = (datetime.utcnow() - start_time).total_seconds()
            self.logger.info(
                f"Discovery completed in {duration:.2f}s. "
                f"Found {len(self.discovered)} subdomains"
            )
            return self.results
            
        except Exception as e:
            self.logger.error(f"Discovery failed: {str(e)}", exc_info=True)
            raise

    async def _process_subdomain(self, domain: str, source: str):
        """Validate and store a discovered subdomain"""
        if domain in self.discovered:
            return
            
        self.discovered.add(domain)
        validation_start = datetime.utcnow()
        
        try:
            # Run validation checks concurrently
            ips, status_result, takeover = await asyncio.gather(
                self.network.resolve_domain(domain),
                self.network.probe_http(domain),
                self.network.check_takeover_vulnerability(domain)
            )
            
            # Extract status from probe result
            status = status_result[0] if status_result else None
            
            # Store results
            result = {
                'domain': domain,
                'source': source,
                'ip_addresses': ips,
                'is_alive': bool(ips),
                'http_status': status,
                'is_takeover_candidate': takeover,
                'discovery_time': datetime.utcnow().isoformat(),
                'last_checked': None
            }
            
            self.results.append(result)
            await self.repository.save(result)
            
            # Log validation results
            validation_duration = (datetime.utcnow() - validation_start).total_seconds()
            self.logger.info(
                f"Processed {domain} in {validation_duration:.1f}s: "
                f"IPs: {len(ips)}, "
                f"HTTP: {status}, "
                f"Takeover: {takeover}"
            )
            
        except Exception as e:
            self.logger.error(f"Failed to process {domain}: {str(e)}")
            raise
