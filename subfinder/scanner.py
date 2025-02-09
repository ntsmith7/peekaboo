import asyncio
import aiohttp
import aiodns
import dns.resolver
import json
import os
from utils.database import db_manager
import socket
import traceback
import uuid
from datetime import datetime
from urllib.parse import urlparse

from utils.logging_config import get_component_logger
from subfinder import Subfinder


class SubdomainFinder:
    def __init__(self, target: str, rate_limit=5):
        self.id = uuid.uuid4()
        self.logger = get_component_logger('finder', include_id=True)
        self.discovered = set()
        self.results = []  # Store results in memory
        self._http_session = None
        self.resolver = aiodns.DNSResolver()
        self.rate_limit = rate_limit
        self.semaphore = asyncio.Semaphore(rate_limit)
        self._http_session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        )
        self.target = self._clean_target(target)
        self.logger.info(f"Initialized SubdomainFinder for target: {self.target} with rate limit: {rate_limit}")

    def _clean_target(self, target: str) -> str:
        original = target
        target = target.lower()
        for prefix in ['https://', 'http://', 'www.']:
            if target.startswith(prefix):
                target = target[len(prefix):]
        cleaned = target.strip('/')
        self.logger.debug(f"Cleaned target from '{original}' to '{cleaned}'")
        return cleaned

    async def resolve_domain(self, domain: str) -> list:
        """Resolve domain to IP addresses"""
        self.logger.debug(f"Resolving IP addresses for {domain}")
        try:
            answers = await self.resolver.query(domain, 'A')
            ips = [answer.host for answer in answers]
            self.logger.debug(f"Resolved {domain} to {ips}")
            return ips
        except Exception as e:
            self.logger.debug(f"Failed to resolve {domain}: {str(e)}")
            return []

    async def find_subdomains(self):
        self.logger.info(f"Starting subdomain discovery for: {self.target}")
        start_time = datetime.utcnow()

        try:
            # Use subfinder for initial passive enumeration
            subfinder = (Subfinder(self.target)
                         .set_rate_limits(global_limit=self.rate_limit)
                         .set_output("temp_results.json", json=True))

            self.logger.debug("Running Subfinder passive enumeration")
            discovered_domains = await subfinder.run()
            self.logger.info(f"Subfinder discovered {len(discovered_domains)} potential subdomains")

            # Process and validate discovered domains
            for domain in discovered_domains:
                await self._store_subdomain(domain, "PASSIVE")

            # Optionally continue with DNS bruteforce for more aggressive scanning
            if hasattr(self, 'include_bruteforce') and self.include_bruteforce:
                self.logger.info("Starting DNS brute-forcing...")
                await self.find_from_dns_bruteforce()

            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()
            self.logger.info(
                f"Discovery completed in {duration:.2f} seconds. "
                f"Found {len(self.discovered)} subdomains"
            )

        except Exception as e:
            self.logger.error(
                f"Error during subdomain discovery: {str(e)}\n"
                f"Traceback: {traceback.format_exc()}"
            )
            raise
        finally:
            if self._http_session:
                await self._http_session.close()
                self.logger.debug("Closed HTTP session")

    async def _check_takeover(self, domain: str):
        self.logger.debug(f"Checking {domain} for potential takeover")
        try:
            answers = await asyncio.get_event_loop().run_in_executor(
                None, lambda: dns.resolver.resolve(domain, 'CNAME')
            )
            cname = str(answers[0].target)
            self.logger.debug(f"CNAME for {domain}: {cname}")

            try:
                await asyncio.get_event_loop().run_in_executor(
                    None, lambda: socket.getaddrinfo(cname, 80)
                )
                return False
            except socket.gaierror:
                self.logger.warning(f"Potential takeover: {domain} -> {cname}")
                return True
        except dns.resolver.NXDOMAIN:
            self.logger.debug(f"No CNAME record found for {domain}")
            return False
        except Exception as e:
            self.logger.error(f"Error checking takeover for {domain}: {str(e)}")
            return False

    async def _probe_http(self, domain: str):
        self.logger.debug(f"Probing HTTP for {domain}")
        try:
            url = f"http://{domain}"
            async with self._http_session.get(url, allow_redirects=False,
                                              timeout=aiohttp.ClientTimeout(total=10)) as response:
                self.logger.debug(f"HTTP probe for {domain} returned status {response.status}")
                return response.status, await response.text()
        except aiohttp.ClientError as e:
            self.logger.debug(f"HTTP probe failed for {domain}: {str(e)}")
            return None, None
        except Exception as e:
            self.logger.error(f"Unexpected error during HTTP probe of {domain}: {str(e)}")
            return None, None

    async def _store_subdomain(self, domain: str, source: str):
        if domain in self.discovered:
            self.logger.debug(f"Skipping already discovered domain: {domain}")
            return

        self.discovered.add(domain)
        self.logger.info(f"Found new subdomain: {domain} from source: {source}")

        try:
            self.logger.debug(f"Starting validation checks for {domain}")
            is_takeover_candidate = await self._check_takeover(domain)
            status, content = await self._probe_http(domain)
            ip_addresses = await self.resolve_domain(domain)

            # Prepare subdomain data
            subdomain_data = {
                'domain': domain,
                'source': source,
                'ip_addresses': ip_addresses,
                'is_alive': bool(ip_addresses),
                'is_takeover_candidate': is_takeover_candidate,
                'http_status': status,
                'discovery_time': datetime.utcnow().isoformat(),
                'last_checked': datetime.utcnow().isoformat()
            }
            
            # Store in memory and database
            self.results.append(subdomain_data)
            
            # Save to database
            with db_manager.session_scope() as session:
                db_manager.save_subdomain(session, subdomain_data)
                
            self.logger.debug(f"Successfully stored {domain} in memory and database")

        except Exception as e:
            self.logger.error(
                f"Error processing {domain}: {str(e)}\n"
                f"Traceback: {traceback.format_exc()}"
            )


class SubdomainScanner:
    def __init__(self, target: str):
        if not target.startswith(('http://', 'https://')):
            target = f'https://{target}'
        self.target = target
        self.logger = get_component_logger('scanner', include_id=True)
        self.logger.info(f"Initialized SubdomainScanner for target: {target}")

    async def run_scan(self):
        """Execute a simplified scan process"""
        self.logger.info(f"Starting scan for target: {self.target}")
        start_time = datetime.utcnow()

        try:
            domain = urlparse(self.target).netloc
            self.logger.debug(f"Parsed domain: {domain}")

            finder = SubdomainFinder(domain)
            await finder.find_subdomains()

            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()
            self.logger.info(f"Scan completed successfully in {duration:.2f} seconds")
            self.logger.info(f"Results saved to {results_file}")

        except Exception as e:
            self.logger.error(
                f"Scan error: {str(e)}\n"
                f"Traceback: {traceback.format_exc()}"
            )
            raise

    @classmethod
    async def scan_target(cls, target: str):
        """Class method to create and run a scanner instance"""
        scanner = cls(target)
        await scanner.run_scan()
