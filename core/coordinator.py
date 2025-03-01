from datetime import datetime
from typing import List, Dict, Optional
import asyncio
import logging
from contextlib import asynccontextmanager

from discovery.discovery import SubdomainDiscovery
from core.utils import clean_target_url
# Import CrawlingService and XSSScanner lazily to avoid circular imports
from core.models import Subdomain, Endpoint, JavaScript, Vulnerability, VulnerabilityType
from infrastructure.database import DatabaseSession


class ScanCoordinator:
    """
    Coordinates a complete security assessment process, managing both
    subdomain discovery and crawling until completion.
    """
    def __init__(self, target: str, db_session: Optional[DatabaseSession] = None):
        self.target = clean_target_url(target)  # Clean target URL for database queries
        self.logger = logging.getLogger(__name__)
        
        # Track scan progress
        self.start_time = None
        self.completion_time = None
        self.total_subdomains = 0
        self.crawled_subdomains = 0
        self.vulnerabilities_found = 0
        self._db_session = db_session

    @asynccontextmanager
    async def _db_context(self):
        """Context manager for database session"""
        if self._db_session:
            # Use existing session if provided
            yield self._db_session
        else:
            # Create new session if none provided
            session = DatabaseSession()
            try:
                self._db_session = session
                yield session
            finally:
                session.close()
                self._db_session = None

    async def start_scan(self, timeout: int = 3600) -> Dict:
        """
        Executes a complete scan of the target, including both subdomain
        discovery and crawling. Returns when all operations are complete.
        
        Args:
            timeout: Maximum time in seconds for the entire scan (default 1 hour)
        """
        self.start_time = datetime.utcnow()
        self.logger.info(f"Starting comprehensive scan of {self.target} (timeout: {timeout}s)")

        try:
            async with self._db_context() as session:
                try:
                    # Create task for the entire scan operation with session
                    self.logger.info("Starting scan operation...")
                    self._db_session = session  # Set session for discovery phase
                    result = await asyncio.wait_for(self._run_scan(session), timeout=timeout)
                    return result
                except asyncio.CancelledError:
                    self.logger.warning("=" * 60)
                    self.logger.warning("Scan cancelled by user")
                    self.logger.warning("Transitioning to crawling phase for discovered subdomains...")
                    self.logger.warning("=" * 60)
                    
                    # Query for any discovered subdomains
                    try:
                        new_active_subdomains = session.query(Subdomain).all()
                        self.logger.info(f"Found domains: {[sub.domain for sub in new_active_subdomains]}")
                        
                        new_count = len(new_active_subdomains)
                        self.logger.info(f"Found {new_count} new active subdomains to crawl")
                        
                        if new_count > 0:
                            self.logger.info("=" * 60)
                            self.logger.info("Starting crawling phase for new active subdomains")
                            self.logger.info("=" * 60)
                            await self._crawl_subdomains(new_active_subdomains, session=session)
                            self.crawled_subdomains = new_count
                        else:
                            self.logger.info("No new active subdomains to crawl")
                    except Exception as e:
                        self.logger.error(f"Error during post-cancellation crawling: {str(e)}", exc_info=True)
                    return self._generate_scan_report(session)
        except asyncio.TimeoutError:
            self.logger.error(f"Scan timed out after {timeout} seconds")
            async with self._db_context() as session:
                return self._generate_scan_report(session, error="Scan timed out")
        except Exception as e:
            self.logger.error(f"Fatal error during scan: {str(e)}", exc_info=True)
            async with self._db_context() as session:
                return self._generate_scan_report(session, error=str(e))

    async def _run_scan(self, session: DatabaseSession) -> Dict:
        """Internal method to run the scan with proper error handling"""
        discoverer = None
        crawler = None

        try:
            # Phase 1: Subdomain Discovery with timeout
            self.logger.info("Starting Phase 1: Subdomain Discovery")
            subdomains = []
            try:
                # Create discoverer with context manager
                discoverer = SubdomainDiscovery(
                    target=self.target,
                    db_session=session,
                    subdomain_model=Subdomain,
                    clean_target_url_func=clean_target_url,
                    rate_limit=10
                )
                async with discoverer:
                    subdomains = await asyncio.wait_for(
                        discoverer.discover(include_bruteforce=False),
                        timeout=900  # 15 minute timeout for discovery
                    )
                self.total_subdomains = len(subdomains)
                self.logger.info(f"Phase 1 Complete: Found {self.total_subdomains} total subdomains")
            except (asyncio.TimeoutError, asyncio.CancelledError) as e:
                self.logger.warning("Subdomain discovery interrupted. Proceeding to crawl any discovered subdomains...")
                # Query database for all subdomains (including base domain)
                subdomains = session.query(Subdomain).filter(
                    (Subdomain.domain == self.target) | (Subdomain.domain.like(f'%.{self.target}'))
                ).all()
                self.total_subdomains = len(subdomains)
                self.logger.info(f"Found {self.total_subdomains} total subdomains in database")

            # Get only new and active subdomains (including base domain)

            
            # Ensure session is fresh
            if not session.is_active:
                self.logger.warning("Session not active, creating new session")
                session = DatabaseSession()
                self._db_session = session
            

            
            query = session.query(Subdomain).filter(
                Subdomain.is_alive == True,
                Subdomain.last_checked == None,
                (Subdomain.domain == self.target) | (Subdomain.domain.like(f'%.{self.target}'))
            )
            self.logger.info(f"Query SQL: {query}")
            
            try:
                new_active_subdomains = query.all()
                self.logger.info(f"Query successful, found domains: {[sub.domain for sub in new_active_subdomains]}")
            except Exception as e:
                self.logger.error(f"Error executing query: {str(e)}")
                self.logger.error(f"Error type: {type(e)}")
                self.logger.error("Full traceback:", exc_info=True)
                raise

            # Phase 2: Crawling with timeout
            self.logger.info("Starting Phase 2: Crawling")
            
            if not new_active_subdomains:
                self.logger.info("No new active subdomains to crawl")
                return self._generate_scan_report(session)

            # Phase 3: Vulnerability Scanning
            self.logger.info("Starting Phase 3: Vulnerability Scanning")
            try:
                await asyncio.wait_for(
                    self._scan_vulnerabilities(session),
                    timeout=900  # 15 minute timeout for vulnerability scanning
                )
            except asyncio.TimeoutError:
                self.logger.error("Vulnerability scanning phase timed out")
                return self._generate_scan_report(session, error="Vulnerability scanning phase timed out")
            except Exception as e:
                self.logger.error(f"Error during vulnerability scanning: {str(e)}")
                return self._generate_scan_report(session, error=str(e))
            
            new_count = len(new_active_subdomains)
            if self.total_subdomains > 0:
                self.logger.info(f"Found {new_count} new active subdomains to crawl ({new_count/self.total_subdomains*100:.1f}% of total)")
            
            self.logger.info("=" * 60)
            self.logger.info("STARTING CRAWLING PHASE")
            self.logger.info("-" * 60)
            self.logger.info(f"Target: {self.target}")
            self.logger.info(f"New active subdomains to crawl: {new_count}")
            self.logger.info(f"Subdomain IDs: {[sub.id for sub in new_active_subdomains]}")
            self.logger.info("=" * 60)
            
            try:
                # Import CrawlingService here to avoid circular imports
                from crawling.service import CrawlingService
                
                # Initialize crawling service with context manager
                crawler = CrawlingService(session)
                async with crawler:
                    self.logger.info("Initialized CrawlingService")
                    
                    # Start the crawl
                    self.logger.info("Initiating crawl operation...")
                    await asyncio.wait_for(
                        crawler.crawl_specific_targets([sub.id for sub in new_active_subdomains]),
                        timeout=1800  # 30 minute timeout for crawling
                    )
                
                # Update progress
                self.crawled_subdomains = new_count
                self.logger.info("=" * 60)
                self.logger.info("CRAWLING PHASE COMPLETE")
                self.logger.info("-" * 60)
                self.logger.info(f"Successfully crawled {self.crawled_subdomains} subdomains")
                self.logger.info("=" * 60)
            except asyncio.TimeoutError:
                self.logger.error("=" * 60)
                self.logger.error("Crawling phase timed out")
                self.logger.error("=" * 60)
                return self._generate_scan_report(session, error="Crawling phase timed out")
            except asyncio.CancelledError:
                self.logger.warning("=" * 60)
                self.logger.warning("Crawling phase cancelled")
                self.logger.warning("Saving partial progress...")
                self.logger.warning("=" * 60)
                raise
            except Exception as e:
                self.logger.error("=" * 60)
                self.logger.error(f"Error during crawling phase: {str(e)}")
                self.logger.error("=" * 60)
                return self._generate_scan_report(session, error=str(e))
            
            # Complete the scan
            self.completion_time = datetime.utcnow()
            self.logger.info("=" * 60)
            self.logger.info("Scan completed successfully")
            self.logger.info("=" * 60)
            return self._generate_scan_report(session)

        except Exception as e:
            self.logger.error(f"Error during scan: {str(e)}", exc_info=True)
            return self._generate_scan_report(session, error=str(e))

    async def _discover_subdomains(self) -> List[Subdomain]:
        """
        Handles the subdomain discovery phase using the unified SubdomainDiscovery class.
        Returns only when all subdomain discovery is complete.
        """
        self.logger.info(f"Starting subdomain discovery for {self.target}")
        
        if not self._db_session:
            self.logger.error("No database session available for subdomain discovery")
            raise RuntimeError("Database session not initialized")
            
        discoverer = SubdomainDiscovery(
            target=self.target,
            db_session=self._db_session,
            subdomain_model=Subdomain,
            clean_target_url_func=clean_target_url,
            rate_limit=10  # Increased rate limit for faster discovery
        )
        
        try:
            async with discoverer:
                subdomains = await discoverer.discover(include_bruteforce=False)
                self.logger.info(f"Subdomain discovery complete. Found {len(subdomains)} subdomains")
                
                # Query the saved subdomains from database to ensure we have the model instances
                subdomain_domains = [s['domain'] for s in subdomains]
                db_subdomains = self._db_session.query(Subdomain).filter(
                    Subdomain.domain.in_(subdomain_domains)
                ).all()
                
                if len(db_subdomains) != len(subdomains):
                    self.logger.warning(f"Found {len(subdomains)} subdomains but only {len(db_subdomains)} were saved to database")
                
                return db_subdomains
                
        except Exception as e:
            self.logger.error(f"Error during subdomain discovery: {str(e)}", exc_info=True)
            raise

    async def _crawl_subdomains(self, subdomains: List[Subdomain], session: Optional[DatabaseSession] = None) -> None:
        """
        Manages the crawling phase. Crawls all provided subdomains
        and returns when crawling is complete.
        
        Args:
            subdomains: List of subdomains to crawl
            session: Optional database session to use (will create new one if not provided)
        """
        self.logger.info(f"Starting crawling phase for {len(subdomains)} subdomains")
        
        # Verify subdomains have IDs
        if not all(hasattr(sub, 'id') for sub in subdomains):
            self.logger.error("Some subdomains are missing IDs - they may not be saved to database")
            return
            
        # Log subdomain details for debugging
        for sub in subdomains:
            self.logger.debug(f"Subdomain to crawl: {sub.domain} (ID: {sub.id}, Alive: {sub.is_alive})")
        
        if session:
            # Import CrawlingService here to avoid circular imports
            from crawling.service import CrawlingService
            
            # Use provided session directly
            crawler = CrawlingService(session)
            async with crawler:
                subdomain_ids = [sub.id for sub in subdomains]
                self.logger.info(f"Starting crawl for {len(subdomain_ids)} subdomain IDs")
                
                try:
                    await crawler.crawl_specific_targets(subdomain_ids)
                    self.logger.info("Crawling phase complete")
                except Exception as e:
                    self.logger.error(f"Error during crawling phase: {str(e)}", exc_info=True)
                    raise
        else:
            # Create new session if none provided
            async with self._db_context() as current_session:
                # Import CrawlingService here to avoid circular imports
                from crawling.service import CrawlingService
                
                crawler = CrawlingService(current_session)
                async with crawler:
                    subdomain_ids = [sub.id for sub in subdomains]
                    self.logger.info(f"Starting crawl for {len(subdomain_ids)} subdomain IDs")
                    
                    try:
                        await crawler.crawl_specific_targets(subdomain_ids)
                        self.logger.info("Crawling phase complete")
                    except Exception as e:
                        self.logger.error(f"Error during crawling phase: {str(e)}", exc_info=True)
                        raise

    async def _scan_vulnerabilities(self, session: DatabaseSession) -> None:
        """
        Handles the vulnerability scanning phase.
        Currently implements XSS scanning, with room for future vulnerability types.
        """
        self.logger.info(f"Starting vulnerability scan for {self.target}")
        
        try:
            # Import XSSScanner here to avoid circular imports
            from vulnerabilites import XSSScanner
            
            # Initialize XSS scanner
            scanner = XSSScanner(session)
            await scanner.setup()
            
            try:
                # Perform XSS scan
                findings = await scanner.scan_target(self.target)
                
                # Save findings to database
                for finding in findings:
                    vulnerability = Vulnerability(
                        endpoint_id=finding.endpoint_id,
                        type=VulnerabilityType.XSS,
                        parameter=finding.parameter,
                        payload=finding.payload,
                        proof=finding.proof,
                        severity=finding.severity,
                        discovery_time=finding.discovery_time,
                        additional_info={}
                    )
                    session.add(vulnerability)
                
                session.commit()
                self.vulnerabilities_found = len(findings)
                self.logger.info(f"Found {self.vulnerabilities_found} XSS vulnerabilities")
                
            finally:
                # Ensure cleanup happens
                await scanner.cleanup()
                
        except Exception as e:
            self.logger.error(f"Error during vulnerability scanning: {str(e)}", exc_info=True)
            raise

    def _generate_scan_report(self, session: DatabaseSession, error: Optional[str] = None) -> Dict:
        """
        Generates a comprehensive report of the scan results.
        
        Args:
            error: Optional error message to include in the report
        """
        self.completion_time = self.completion_time or datetime.utcnow()
        duration = (self.completion_time - self.start_time).total_seconds()
        endpoints = self._count_endpoints(session) if not error else 0
        js_files = self._count_js_files(session) if not error else 0
        vulnerabilities = self._count_vulnerabilities(session) if not error else 0
        
        report = {
            'target': self.target,
            'start_time': self.start_time.isoformat(),
            'completion_time': self.completion_time.isoformat(),
            'duration_seconds': duration,
            'total_subdomains': self.total_subdomains,
            'status': 'error' if error else 'completed',
            'statistics': {
                'live_subdomains': self.crawled_subdomains,
                'endpoints_discovered': endpoints,
                'js_files_found': js_files,
                'vulnerabilities_found': vulnerabilities
            }
        }
        
        if error:
            report['error'] = error
        
        # Log summary
        status = f"ERROR: {error}" if error else "SUCCESS"
        self.logger.info(f"""
Scan Summary:
-------------
Target: {self.target}
Status: {status}
Duration: {duration:.1f} seconds
Total Subdomains: {self.total_subdomains}
Live Subdomains: {self.crawled_subdomains}
Endpoints Found: {endpoints}
JavaScript Files: {js_files}
        """.strip())
        
        return report

    def _count_endpoints(self, session: DatabaseSession) -> int:
        """Counts total endpoints discovered during the scan"""
        return session.query(Endpoint).join(Subdomain).filter(
            (Subdomain.domain == self.target) | (Subdomain.domain.like(f'%.{self.target}'))
        ).count()

    def _count_js_files(self, session: DatabaseSession) -> int:
        """Counts total JavaScript files discovered during the scan"""
        return session.query(JavaScript).join(Subdomain).filter(
            (Subdomain.domain == self.target) | (Subdomain.domain.like(f'%.{self.target}'))
        ).count()
        
    def _count_vulnerabilities(self, session: DatabaseSession) -> int:
        """Counts total vulnerabilities found during the scan"""
        return session.query(Vulnerability).join(Endpoint).join(Subdomain).filter(
            (Subdomain.domain == self.target) | (Subdomain.domain.like(f'%.{self.target}'))
        ).count()
