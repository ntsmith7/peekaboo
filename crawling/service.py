# scanner/crawling/service.py

from datetime import datetime, timedelta
from typing import List, Optional, Dict, TYPE_CHECKING

if TYPE_CHECKING:
    from core.models import KatanaResult
import asyncio
import logging

from core.models import Subdomain, Endpoint, JavaScript, EndpointSource
from .katana import KatanaCrawler
from infrastrucutre.database import DatabaseSession

class CrawlingService:
    """
    Independent service for managing web crawling operations.
    This service can run on its own schedule and manage its own workload,
    separate from the subdomain discovery process.
    """
    def __init__(self, db_session: DatabaseSession):
        self.session = db_session
        self.logger = logging.getLogger(__name__)
        
        # Configure crawling parameters
        self.max_concurrent_crawls = 5
        self.crawl_semaphore = asyncio.Semaphore(self.max_concurrent_crawls)
        self.katana = KatanaCrawler()

    async def start_crawling_service(self):
        """
        Main entry point for the crawling service.
        This runs continuously, checking for subdomains that need crawling.
        """
        self.logger.info("Starting crawling service")
        consecutive_errors = 0
        
        while True:
            try:
                # Get subdomains that need crawling with timeout
                try:
                    subdomains = await asyncio.wait_for(
                        self._get_pending_crawls(),
                        timeout=30  # 30 second timeout for database query
                    )
                except asyncio.TimeoutError:
                    self.logger.error("Timeout getting pending crawls from database")
                    await asyncio.sleep(60)
                    continue
                
                if subdomains:
                    self.logger.info(f"Found {len(subdomains)} subdomains to crawl")
                    # Create tasks for each subdomain with individual timeouts
                    tasks = []
                    for sub in subdomains:
                        task = asyncio.create_task(self._crawl_subdomain(sub))
                        tasks.append(task)
                    
                    # Run crawls concurrently with overall timeout
                    try:
                        await asyncio.wait_for(
                            asyncio.gather(*tasks, return_exceptions=True),
                            timeout=300  # 5 minute timeout for batch
                        )
                    except asyncio.TimeoutError:
                        self.logger.error("Batch crawl operation timed out")
                        # Cancel any remaining tasks
                        for task in tasks:
                            if not task.done():
                                task.cancel()
                
                # Reset error counter on successful iteration
                consecutive_errors = 0
                
                # Wait before next check
                await asyncio.sleep(300)  # 5 minutes between checks
                
            except Exception as e:
                consecutive_errors += 1
                self.logger.error(f"Error in crawling service (attempt {consecutive_errors}): {str(e)}")
                
                # Exponential backoff with max delay of 5 minutes
                delay = min(60 * 2 ** (consecutive_errors - 1), 300)
                self.logger.info(f"Waiting {delay} seconds before retry")
                await asyncio.sleep(delay)
                
                # If too many consecutive errors, restart the service
                if consecutive_errors >= 5:
                    self.logger.error("Too many consecutive errors, restarting crawling service")
                    return  # Let the context manager restart us

    async def crawl_specific_targets(self, subdomain_ids: List[int]):
        """
        Crawl specific subdomains by their IDs.
        This allows for on-demand crawling of particular targets.
        """
        self.logger.info("=" * 60)
        self.logger.info("STARTING CRAWL OPERATION")
        self.logger.info("-" * 60)
        self.logger.info(f"Subdomain IDs to crawl: {subdomain_ids}")
        self.logger.info("=" * 60)
        
        try:
            self.logger.info("Fetching subdomains from database...")
            subdomains = self.session.query(Subdomain).filter(
                Subdomain.id.in_(subdomain_ids)
            ).all()
            
            if not subdomains:
                self.logger.error("=" * 60)
                self.logger.error("No subdomains found in database for the given IDs")
                self.logger.error("=" * 60)
                return
                
            self.logger.info(f"Successfully fetched {len(subdomains)} subdomains")
            
            # Create tasks with progress tracking
            tasks = []
            self.logger.info("=" * 60)
            self.logger.info("CRAWLING PHASE STARTING")
            self.logger.info("=" * 60)
            for i, sub in enumerate(subdomains, 1):
                self.logger.info(f"[{i}/{len(subdomains)}] Scheduling crawl for: {sub.domain}")
                task = self._crawl_subdomain(sub)
                tasks.append(task)
            
            # Run crawls with progress updates
            self.logger.info("=" * 60)
            self.logger.info(f"Beginning concurrent crawl of {len(tasks)} subdomains")
            self.logger.info("This may take several minutes...")
            self.logger.info("=" * 60)
            
            try:
                self.logger.info("=" * 60)
                self.logger.info("STARTING CRAWL OPERATIONS")
                self.logger.info("=" * 60)
                
                results = await asyncio.gather(*tasks, return_exceptions=True)
                success_count = sum(1 for r in results if not isinstance(r, Exception))
                
                self.logger.info("=" * 60)
                self.logger.info(f"CRAWL COMPLETE: {success_count}/{len(tasks)} subdomains processed")
                self.logger.info("=" * 60)
                
            except asyncio.CancelledError:
                self.logger.warning("=" * 60)
                self.logger.warning("CRAWL CANCELLED BY USER")
                self.logger.warning("Attempting to save partial progress...")
                self.logger.warning("=" * 60)
                
                # Count completed tasks before cancellation
                completed = sum(1 for task in tasks if task.done() and not isinstance(task.result(), Exception))
                remaining = sum(1 for task in tasks if not task.done())
                
                self.logger.info(f"Successfully crawled: {completed} subdomains")
                self.logger.info(f"Remaining (cancelled): {remaining} subdomains")
                
                # Cancel remaining tasks
                for task in tasks:
                    if not task.done():
                        task.cancel()
                        
                self.logger.info("All remaining tasks cancelled")
                raise
            
            # Detailed error logging
            for sub, result in zip(subdomains, results):
                if isinstance(result, Exception):
                    self.logger.error("=" * 60)
                    self.logger.error(f"Failed to crawl: {sub.domain}")
                    self.logger.error(f"Error: {str(result)}")
                    self.logger.error(f"Type: {type(result).__name__}")
                    self.logger.error("=" * 60)
                    
        except Exception as e:
            self.logger.error(f"Error in crawl_specific_targets: {str(e)}", exc_info=True)
            raise

    async def _get_pending_crawls(self) -> List[Subdomain]:
        """
        Find subdomains that need to be crawled based on various criteria.
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=24)
        
        return self.session.query(Subdomain).filter(
            # Never crawled or not crawled recently
            ((Subdomain.last_checked == None) | 
             (Subdomain.last_checked < cutoff_time)),
            # Only crawl live subdomains
            Subdomain.is_alive == True
        ).limit(50).all()  # Process in batches

    async def _crawl_subdomain(self, subdomain: Subdomain):
        """
        Perform the actual crawling of a subdomain with proper resource management.
        """
        async with self.crawl_semaphore:
            start_time = datetime.utcnow()
            self.logger.info("=" * 60)
            self.logger.info(f"Starting crawl of: {subdomain.domain}")
            self.logger.info(f"Subdomain ID: {subdomain.id}")
            self.logger.info(f"Status: {'Live' if subdomain.is_alive else 'Dead'}")
            self.logger.info("=" * 60)
            try:
                # Use your existing KatanaCrawler with timeout
                try:
                    results = await asyncio.wait_for(
                        self.katana.crawl_all(f"https://{subdomain.domain}"),
                        timeout=120  # 2 minute timeout per subdomain
                    )
                except asyncio.TimeoutError:
                    self.logger.error(f"Crawl timed out for {subdomain.domain}")
                    return
                
                # Log crawl statistics
                duration = (datetime.utcnow() - start_time).total_seconds()
                endpoints = sum(1 for r in results if not r.url.endswith('.js'))
                js_files = sum(1 for r in results if r.url.endswith('.js'))
                rate = len(results) / duration if duration > 0 else 0
                
                self.logger.info("=" * 60)
                self.logger.info(f"CRAWL COMPLETE: {subdomain.domain}")
                self.logger.info("-" * 60)
                self.logger.info(f"Duration: {duration:.1f} seconds")
                self.logger.info(f"Total URLs: {len(results)}")
                self.logger.info(f"Endpoints: {endpoints}")
                self.logger.info(f"JavaScript Files: {js_files}")
                self.logger.info(f"Processing Rate: {rate:.1f} URLs/second")
                self.logger.info("=" * 60)
                
                # Process and store results with timeout
                try:
                    await asyncio.wait_for(
                        self._process_results(subdomain.id, results),
                        timeout=60  # 1 minute timeout for processing
                    )
                except asyncio.TimeoutError:
                    self.logger.error(f"Result processing timed out for {subdomain.domain}")
                    return
                
                # Update subdomain status
                try:
                    subdomain.last_checked = datetime.utcnow()
                    self.session.commit()
                except Exception as e:
                    self.logger.error(f"Failed to update last_checked for {subdomain.domain}: {str(e)}")
                
            except Exception as e:
                self.logger.error(f"Error crawling {subdomain.domain}: {str(e)}", exc_info=True)
                # Error is contained and won't affect other crawls

    def _create_endpoint_record(self, subdomain_id: int, result: 'KatanaResult') -> Endpoint:
        """Create an Endpoint record from a KatanaResult"""
        return Endpoint(
            subdomain_id=subdomain_id,
            path=result.url,
            method=result.method,
            source=EndpointSource(result.source),
            discovery_time=datetime.utcnow(),
            content_type=result.content_type,
            status_code=result.status_code,
            response_size=result.response_size,
            parameters=result.parameters,
            is_authenticated=False,  # Default to unauthenticated
            additional_info={
                'headers': result.headers,
                'response_body': result.response_body
            }
        )

    def _create_js_record(self, subdomain_id: int, result: 'KatanaResult') -> JavaScript:
        """Create a JavaScript record from a KatanaResult"""
        return JavaScript(
            subdomain_id=subdomain_id,
            url=result.url,
            file_hash=None,  # Could implement hashing if needed
            endpoints_referenced=[],  # Would need additional parsing
            variables={},  # Would need additional parsing
            discovery_time=datetime.utcnow(),
            last_modified=None  # Could parse from headers if needed
        )

    async def _process_results(self, subdomain_id: int, results: List['KatanaResult']):
        """
        Process and store the results from a crawl.
        """
        try:
            endpoints = []
            js_files = []
            total_results = len(results)
            
            for i, result in enumerate(results, 1):
                if i % 100 == 0:  # Log progress every 100 items
                    self.logger.info(f"Processing results: {i}/{total_results} ({i/total_results*100:.1f}%) - {subdomain_id}")
                
                if result.url.endswith('.js'):
                    js_files.append(self._create_js_record(subdomain_id, result))
                else:
                    endpoints.append(self._create_endpoint_record(subdomain_id, result))
            
            # Log final counts before database insertion
            self.logger.info(f"Preparing to save: {len(endpoints)} endpoints and {len(js_files)} JavaScript files")
            
            # Batch insert records for better performance
            if endpoints:
                self.logger.info("Saving endpoints to database...")
                self.session.bulk_save_objects(endpoints)
            if js_files:
                self.logger.info("Saving JavaScript files to database...")
                self.session.bulk_save_objects(js_files)
                
            self.session.commit()
            self.logger.info("Successfully saved all results to database")
            
        except Exception as e:
            self.logger.error(f"Error processing results: {str(e)}")
            self.session.rollback()
            raise
