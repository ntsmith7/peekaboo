import asyncio
import aiohttp
import aiodns
import dns.resolver
import json
import os
import socket
import traceback
import uuid
from datetime import datetime
from urllib.parse import urlparse

from infrastrucutre.database import DatabaseSession
from infrastrucutre.logging_config import get_logger


class SubdomainDiscovery:
    """
    Unified class for subdomain discovery combining passive and active techniques.
    """
    def __init__(self, target: str, db_session: DatabaseSession, subdomain_model, clean_target_url_func, rate_limit=5):
        self.logger = get_logger(__name__)
        self.session = db_session
        self.id = uuid.uuid4()
        self.discovered = set()
        self.results = []  # Store results in memory
        self._http_session = None
        self.resolver = None
        self.rate_limit = rate_limit
        self.semaphore = asyncio.Semaphore(rate_limit)
        self.target = clean_target_url_func(target)
        self.subdomain_model = subdomain_model
        self._cleanup_lock = asyncio.Lock()
        self._is_closed = False
        self.logger.info(f"Initialized SubdomainDiscovery for target: {self.target} with rate limit: {rate_limit}")

    async def __aenter__(self):
        """Async context manager entry"""
        await self.setup()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.cleanup()

    async def setup(self):
        """Initialize async resources"""
        if not self._http_session:
            self._http_session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
        if not self.resolver:
            self.resolver = aiodns.DNSResolver()
        self._is_closed = False

    async def cleanup(self):
        """Cleanup async resources"""
        async with self._cleanup_lock:
            if self._is_closed:
                return

            self.logger.debug("Starting SubdomainDiscovery cleanup")
            try:
                if self._http_session:
                    await asyncio.wait_for(self._http_session.close(), timeout=5)
                self._http_session = None
                self.resolver = None
                self._is_closed = True
                self.logger.debug("SubdomainDiscovery cleanup completed")
            except asyncio.TimeoutError:
                self.logger.error("Timeout during SubdomainDiscovery cleanup")
            except Exception as e:
                self.logger.error(f"Error during SubdomainDiscovery cleanup: {str(e)}")

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

    async def discover(self, include_bruteforce=False):
        """
        Main discovery method combining passive and active techniques.
        """
        if self._is_closed:
            raise RuntimeError("SubdomainDiscovery is closed")

        # Reset collections at the start of each scan
        self.discovered = set()
        self.results = []
        
        self.logger.info(f"Starting subdomain discovery for: {self.target}")
        start_time = datetime.utcnow()

        try:
            await self.setup()  # Ensure resources are initialized

            # Always check base domain first
            await self._store_subdomain(self.target, "PASSIVE")
            
            # Run passive enumeration using subfinder command
            await self._passive_enumeration()

            # Optionally perform DNS bruteforce
            if include_bruteforce:
                self.logger.info("Starting DNS brute-forcing...")
                await self._dns_bruteforce()

            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()
            self.logger.info(
                f"Discovery completed in {duration:.2f} seconds. "
                f"Found {len(self.discovered)} subdomains"
            )
            return self.results

        except asyncio.CancelledError:
            self.logger.warning("Discovery cancelled")
            raise
        except Exception as e:
            self.logger.error(
                f"Error during subdomain discovery: {str(e)}\n"
                f"Traceback: {traceback.format_exc()}"
            )
            raise

    async def _passive_enumeration(self):
        """
        Perform passive subdomain enumeration using subfinder.
        """
        cmd = [
            'subfinder',
            '-d', self.target,
            '-silent',
            '-json',
            '-timeout', '30'  # Add timeout to prevent hanging
        ]

        if self.rate_limit:
            cmd.extend(['-rate-limit', str(self.rate_limit)])

        self.logger.debug(f"Executing command: {' '.join(cmd)}")

        try:
            # Create subprocess with timeout
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            # Wait for the process with timeout
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=300  # 5 minute timeout for the entire operation
                )
            except asyncio.TimeoutError:
                process.kill()
                self.logger.error("Subfinder process timed out after 300 seconds")
                return

            if process.returncode != 0:
                error_msg = stderr.decode()
                self.logger.error(f"Subfinder execution failed: {error_msg}")
                return  # Continue with empty results instead of raising

            # Parse JSON output line by line with timeout protection
            stdout_text = stdout.decode()
            if not stdout_text.strip():
                self.logger.warning("No output from subfinder")
                return

            lines = stdout_text.splitlines()
            total_lines = len(lines)
            self.logger.info(f"Processing {total_lines} results from subfinder")

            for i, line in enumerate(lines, 1):
                if i % 10 == 0:  # Log progress every 10 subdomains
                    self.logger.info(f"Processing subfinder results: {i}/{total_lines} ({i/total_lines*100:.1f}%)")
                try:
                    data = json.loads(line)
                    # Use asyncio.wait_for to prevent hanging on store operations
                    await asyncio.wait_for(
                        self._store_subdomain(data['host'], "PASSIVE"),
                        timeout=10  # 10 second timeout for storing each subdomain
                    )
                except asyncio.TimeoutError:
                    self.logger.error(f"Timeout storing subdomain from line: {line}")
                    continue
                except json.JSONDecodeError:
                    self.logger.warning(f"Failed to parse JSON line: {line}")
                    continue
                except KeyError:
                    self.logger.warning(f"Missing 'host' key in JSON data: {line}")
                    continue

            self.logger.info(f"Completed processing {total_lines} subfinder results")

        except FileNotFoundError:
            self.logger.error("Subfinder binary not found in system PATH")
            return  # Continue with empty results instead of raising
        except Exception as e:
            self.logger.error(f"Unexpected error in passive enumeration: {str(e)}")
            return  # Continue with empty results instead of raising

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
        """Store subdomain information in memory and database."""
        if domain in self.discovered:
            self.logger.debug(f"Skipping already discovered domain: {domain}")
            return

        self.discovered.add(domain)
        validation_start = datetime.utcnow()

        try:
            # Perform validation checks
            is_takeover_candidate = await self._check_takeover(domain)
            status, _ = await self._probe_http(domain)
            ip_addresses = await self.resolve_domain(domain)
            is_alive = bool(ip_addresses)
            current_time = datetime.utcnow()

            # Store result in memory
            self.results.append({
                'domain': domain,
                'source': source,
                'ip_addresses': ip_addresses,
                'is_alive': is_alive,
                'is_takeover_candidate': is_takeover_candidate,
                'http_status': status,
                'discovery_time': current_time.isoformat(),
                'last_checked': current_time.isoformat()
            })

            # Check if subdomain already exists
            existing = self.session.session.query(self.subdomain_model).filter(self.subdomain_model.domain == domain).first()
            
            if existing:
                # Update existing record
                existing.source = source
                existing.ip_addresses = ip_addresses
                existing.is_alive = is_alive
                existing.is_takeover_candidate = is_takeover_candidate
                existing.http_status = status
                existing.discovery_time = current_time
                existing.last_checked = None  # Reset to trigger crawl
            else:
                # Create new record
                subdomain = self.subdomain_model(
                    domain=domain,
                    source=source,
                    ip_addresses=ip_addresses,
                    is_alive=is_alive,
                    is_takeover_candidate=is_takeover_candidate,
                    http_status=status,
                    discovery_time=current_time,
                    last_checked=None  # Reset to trigger crawl
                )
                self.session.session.add(subdomain)
            
            try:
                self.session.session.commit()
            except Exception as e:
                self.logger.error(f"Database error for {domain}: {str(e)}")
                self.session.session.rollback()
                raise

            # Log validation results
            validation_duration = (datetime.utcnow() - validation_start).total_seconds()
            self.logger.info(
                f"Processed {domain} in {validation_duration:.1f}s: "
                f"IPs: {len(ip_addresses)}, "
                f"HTTP: {status}, "
                f"Takeover: {is_takeover_candidate}, "
                f"Status: {'Live' if is_alive else 'Dead'}"
            )

        except Exception as e:
            self.logger.error(f"Error processing {domain}: {str(e)}")
            raise
