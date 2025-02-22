import aiohttp
import aiodns
import dns.resolver
import socket
import asyncio
from typing import Tuple, List, Optional
from infrastructure.logging_config import get_logger

class NetworkOperations:
    """
    Handles all network-related operations for subdomain discovery including
    HTTP probing and DNS resolution.
    """
    def __init__(self, timeout: int = 30):
        self.logger = get_logger(__name__)
        self._http_session = None
        self.resolver = None
        self.timeout = timeout

    async def setup(self):
        """Initialize network resources with proper timeouts and headers"""
        if not self._http_session:
            self._http_session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
        if not self.resolver:
            self.resolver = aiodns.DNSResolver()

    async def cleanup(self):
        """Clean up network resources safely"""
        if self._http_session:
            await self._http_session.close()
        self._http_session = None
        self.resolver = None

    async def resolve_domain(self, domain: str) -> List[str]:
        """Resolve a domain to its IP addresses"""
        self.logger.debug(f"Resolving IP addresses for {domain}")
        try:
            answers = await self.resolver.query(domain, 'A')
            ips = [answer.host for answer in answers]
            self.logger.debug(f"Resolved {domain} to {ips}")
            return ips
        except Exception as e:
            self.logger.debug(f"Failed to resolve {domain}: {str(e)}")
            return []

    async def check_takeover_vulnerability(self, domain: str) -> bool:
        """Check if a domain is vulnerable to takeover via CNAME verification"""
        self.logger.debug(f"Checking {domain} for potential takeover")
        try:
            answers = await asyncio.get_event_loop().run_in_executor(
                None, lambda: dns.resolver.resolve(domain, 'CNAME')
            )
            cname = str(answers[0].target)
            
            try:
                await asyncio.get_event_loop().run_in_executor(
                    None, lambda: socket.getaddrinfo(cname, 80)
                )
                return False
            except socket.gaierror:
                self.logger.warning(f"Potential takeover: {domain} -> {cname}")
                return True
        except Exception as e:
            self.logger.debug(f"No takeover vulnerability found for {domain}: {str(e)}")
            return False

    async def probe_http(self, domain: str) -> Tuple[Optional[int], Optional[str]]:
        """Probe a domain via HTTP to check its status"""
        self.logger.debug(f"Probing HTTP for {domain}")
        try:
            url = f"http://{domain}"
            async with self._http_session.get(
                url, 
                allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                self.logger.debug(f"HTTP probe for {domain} returned status {response.status}")
                return response.status, await response.text()
        except Exception as e:
            self.logger.debug(f"HTTP probe failed for {domain}: {str(e)}")
            return None, None
