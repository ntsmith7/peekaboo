# scanner/core/coordinator.py
from datetime import datetime
from typing import List, Dict, Optional
import asyncio
import logging
from contextlib import asynccontextmanager

from discovery.scanner import SubdomainDiscovery
from crawling.service import CrawlingService
from core.models import Subdomain, Endpoint, JavaScript
from infrastrucutre.database import DatabaseSession


class ScanCoordinator:
    """
    Coordinates a complete security assessment process, managing both
    subdomain discovery and crawling until completion.
    """
    def __init__(self, target: str, db_session: Optional[DatabaseSession] = None):
        self.target = target
        self.logger = logging.getLogger(__name__)
        
        # Track scan progress
        self.start_time = None
        self.completion_time = None
        self.total_subdomains = 0
        self.crawled_subdomains = 0
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
                    scan_task = asyncio.create_task(self._run_scan(session))  # Pass session to _run_scan
                    result = await asyncio.wait_for(scan_task, timeout=timeout)
                    return result  # Return the result from _run_scan directly
                except asyncio.CancelledError:
                    self.logger.warning("=" * 60)
                    self.logger.warning("Scan cancelled by user")
                    self.logger.warning("Transitioning to crawling phase for discovered subdomains...")
                    self.logger.warning("=" * 60)
                    
                    # Query for any discovered live subdomains
                    try:
                        total_subdomains = session.query(Subdomain).filter(
                            Subdomain.domain.like(f'%.{self.target}')
                        ).count()
                        
                        live_subdomains = session.query(Subdomain).filter(
                            Subdomain.domain.like(f'%.{self.target}'),
                            Subdomain.is_alive == True
                        ).all()
                        
                        self.total_subdomains = total_subdomains
                        live_count = len(live_subdomains)
                        
                        self.logger.info(f"Found {total_subdomains} total subdomains")
                        self.logger.info(f"Found {live_count} live subdomains to crawl ({live_count/total_subdomains*100:.1f}% of total)")
                        
                        # Always proceed with crawling phase
                        self.logger.info("=" * 60)
                        self.logger.info("Starting crawling phase for discovered live subdomains")
                        self.logger.info("=" * 60)
                        if live_count == 0:
                            self.logger.warning("No live subdomains found to crawl")
                            self.logger.info("Proceeding with crawl phase anyway...")
                        await self._crawl_subdomains(live_subdomains, session=session)
                        self.crawled_subdomains = live_count
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
        try:
            # Phase 1: Subdomain Discovery with timeout
            self.logger.info("Starting Phase 1: Subdomain Discovery")
            subdomains = []
            try:
                subdomains = await asyncio.wait_for(
                    self._discover_subdomains(),
                    timeout=900  # 15 minute timeout for discovery
                )
                self.total_subdomains = len(subdomains)
                self.logger.info(f"Phase 1 Complete: Found {self.total_subdomains} total subdomains")
            except (asyncio.TimeoutError, asyncio.CancelledError) as e:
                self.logger.warning("Subdomain discovery interrupted. Proceeding to crawl any discovered subdomains...")
                # Query database for any subdomains that were saved before interruption
                subdomains = session.query(Subdomain).filter(
                    Subdomain.domain.like(f'%.{self.target}')
                ).all()
                self.total_subdomains = len(subdomains)
                self.logger.info(f"Found {self.total_subdomains} subdomains in database")

            # Phase 2: Crawling with timeout
            self.logger.info("Starting Phase 2: Crawling")
            live_subdomains = [sub for sub in subdomains if sub.is_alive]
            live_count = len(live_subdomains)
            
            if live_count == 0:
                self.logger.warning("No live subdomains found to crawl")
                self.logger.info("Proceeding with crawl phase anyway...")
            else:
                self.logger.info(f"Found {live_count} live subdomains to crawl ({live_count/self.total_subdomains*100:.1f}% of total)")
            
            # Always proceed with crawling phase
            self.logger.info("=" * 60)
            self.logger.info("STARTING CRAWLING PHASE")
            self.logger.info("-" * 60)
            self.logger.info(f"Target: {self.target}")
            self.logger.info(f"Live subdomains to crawl: {live_count}")
            if live_count > 0:
                self.logger.info(f"Subdomain IDs: {[sub.id for sub in live_subdomains]}")
            self.logger.info("=" * 60)
            
            try:
                # Initialize crawling service with our session
                crawler = CrawlingService(session)
                self.logger.info("Initialized CrawlingService")
                
                # Start the crawl
                self.logger.info("Initiating crawl operation...")
                await asyncio.wait_for(
                    crawler.crawl_specific_targets([sub.id for sub in live_subdomains]),
                    timeout=1800  # 30 minute timeout for crawling
                )
                
                # Update progress
                self.crawled_subdomains = live_count
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
            rate_limit=10  # Increased rate limit for faster discovery
        )
        
        try:
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
            # Use provided session directly
            crawler = CrawlingService(session)
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
                crawler = CrawlingService(current_session)
                subdomain_ids = [sub.id for sub in subdomains]
                self.logger.info(f"Starting crawl for {len(subdomain_ids)} subdomain IDs")
                
                try:
                    await crawler.crawl_specific_targets(subdomain_ids)
                    self.logger.info("Crawling phase complete")
                except Exception as e:
                    self.logger.error(f"Error during crawling phase: {str(e)}", exc_info=True)
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
                'js_files_found': js_files
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
            Subdomain.domain.like(f'%.{self.target}')).count()

    def _count_js_files(self, session: DatabaseSession) -> int:
        """Counts total JavaScript files discovered during the scan"""
        return session.query(JavaScript).join(Subdomain).filter(
            Subdomain.domain.like(f'%.{self.target}')).count()
