from datetime import datetime
from typing import List, Optional, Dict, TYPE_CHECKING

if TYPE_CHECKING:
    from core.models import KatanaResult
import asyncio
import logging

from core.models import Subdomain, Endpoint, JavaScript, EndpointSource
from .katana import KatanaCrawler
from infrastrucutre.database import DatabaseSession

class CrawlingService:
    """Service for managing web crawling operations."""
    def __init__(self, db_session: DatabaseSession):
        self.session = db_session
        self.logger = logging.getLogger(__name__)
        self.max_concurrent_crawls = 5
        self.crawl_semaphore = asyncio.Semaphore(self.max_concurrent_crawls)
        self.katana = None  # Initialize in async setup
        self._cleanup_lock = asyncio.Lock()
        self._is_closed = False

    async def __aenter__(self):
        """Async context manager entry"""
        await self.setup()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.cleanup()

    async def setup(self):
        """Initialize async resources"""
        if not self.katana:
            self.katana = KatanaCrawler()
        self._is_closed = False

    async def cleanup(self):
        """Cleanup async resources"""
        async with self._cleanup_lock:
            if self._is_closed:
                return
            
            self.logger.debug("Starting CrawlingService cleanup")
            try:
                if self.katana:
                    await asyncio.wait_for(self.katana.close(), timeout=5)
                self._is_closed = True
                self.logger.debug("CrawlingService cleanup completed")
            except asyncio.TimeoutError:
                self.logger.error("Timeout during CrawlingService cleanup")
            except Exception as e:
                self.logger.error(f"Error during CrawlingService cleanup: {str(e)}")

    async def crawl_specific_targets(self, subdomain_ids: List[int]):
        """Crawl specific subdomains by their IDs."""
        if self._is_closed:
            raise RuntimeError("CrawlingService is closed")

        self.logger.info(f"Starting crawl for {len(subdomain_ids)} subdomains")
        
        try:
            await self.setup()  # Ensure resources are initialized
            subdomains = self.session.query(Subdomain).filter(
                Subdomain.id.in_(subdomain_ids)
            ).all()
            
            if not subdomains:
                self.logger.warning("No subdomains found for the given IDs")
                return
            
            tasks = [self._crawl_subdomain(sub) for sub in subdomains]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            success_count = sum(1 for r in results if not isinstance(r, Exception))
            self.logger.info(f"Completed crawling {success_count}/{len(tasks)} subdomains")
            
            for sub, result in zip(subdomains, results):
                if isinstance(result, Exception):
                    self.logger.error(f"Failed to crawl {sub.domain}: {str(result)}")
                    
        except Exception as e:
            self.logger.error(f"Error in crawl_specific_targets: {str(e)}")
            raise

    async def _crawl_subdomain(self, subdomain: Subdomain):
        """Crawl a single subdomain."""
        if self._is_closed:
            raise RuntimeError("CrawlingService is closed")

        async with self.crawl_semaphore:
            try:
                url = f"https://{subdomain.domain}"
                self.logger.info(f"Crawling: {url}")
                
                try:
                    results = await asyncio.wait_for(
                        self.katana.crawl_all(url),
                        timeout=180
                    )
                except asyncio.CancelledError:
                    self.logger.warning(f"Crawl cancelled for {url}")
                    raise
                except asyncio.TimeoutError:
                    self.logger.error(f"Crawl timed out for {url}")
                    return
                
                if not results:
                    self.logger.warning(f"No results for {subdomain.domain}")
                    return
                
                await self._process_results(subdomain.id, results)
                
                # Update last_checked
                subdomain.last_checked = datetime.utcnow()
                self.session.commit()
                
            except asyncio.TimeoutError:
                self.logger.error(f"Timeout crawling {subdomain.domain}")
            except Exception as e:
                self.logger.error(f"Error crawling {subdomain.domain}: {str(e)}")
                raise

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
            is_authenticated=False,
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
            file_hash=None,
            endpoints_referenced=[],
            variables={},
            discovery_time=datetime.utcnow(),
            last_modified=None
        )

    async def _process_results(self, subdomain_id: int, results: List['KatanaResult']):
        """Process and store crawl results."""
        try:
            endpoints = []
            js_files = []
            
            for result in results:
                if result.url.endswith('.js'):
                    js_files.append(self._create_js_record(subdomain_id, result))
                else:
                    endpoints.append(self._create_endpoint_record(subdomain_id, result))
            
            if endpoints:
                self.session.bulk_save_objects(endpoints)
            if js_files:
                self.session.bulk_save_objects(js_files)
                
            self.session.commit()
            
        except Exception as e:
            self.logger.error(f"Error processing results: {str(e)}")
            self.session.rollback()
            raise
