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

from .utils import clean_target_url
from infrastrucutre.logging_config import get_component_logger
from infrastrucutre.database import DatabaseSession
from core.models import Subdomain


class SubdomainDiscovery:
    """
    Unified class for subdomain discovery combining passive and active techniques.
    """
    def __init__(self, target: str, db_session: DatabaseSession, rate_limit=5):
        self.session = db_session
        self.id = uuid.uuid4()
        self.logger = get_component_logger('subdomain_discovery', include_id=True)
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
        self.target = clean_target_url(target)
        self.logger.info(f"Initialized SubdomainDiscovery for target: {self.target} with rate limit: {rate_limit}")

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
        self.logger.info(f"Starting subdomain discovery for: {self.target}")
        start_time = datetime.utcnow()

        try:
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
        if domain in self.discovered:
            self.logger.debug(f"Skipping already discovered domain: {domain}")
            return

        self.discovered.add(domain)
        self.logger.info(f"Found new subdomain: {domain} from source: {source}")

        try:
            self.logger.info(f"Starting validation checks for {domain}")
            validation_start = datetime.utcnow()
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
            
            # Create Subdomain model instance
            subdomain = Subdomain(
                domain=domain,
                source=source,
                ip_addresses=ip_addresses,
                is_alive=bool(ip_addresses),
                is_takeover_candidate=is_takeover_candidate,
                http_status=status,
                discovery_time=datetime.utcnow(),
                last_checked=datetime.utcnow()
            )
            
            # Save to database using provided session and commit immediately
            try:
                self.session.add(subdomain)
                self.session.commit()
                self.logger.info(f"Successfully saved {domain} to database")
            except Exception as e:
                self.logger.error(f"Failed to save {domain} to database: {str(e)}")
                self.session.rollback()
                raise
            
            validation_duration = (datetime.utcnow() - validation_start).total_seconds()
            self.logger.info(f"""
Validation complete for {domain}:
- Duration: {validation_duration:.1f} seconds
- IP Addresses: {len(ip_addresses)}
- HTTP Status: {status}
- Takeover Candidate: {is_takeover_candidate}
- Status: {'Live' if bool(ip_addresses) else 'Dead'}
            """.strip())

        except Exception as e:
            self.logger.error(
                f"Error processing {domain}: {str(e)}\n"
                f"Traceback: {traceback.format_exc()}"
            )
