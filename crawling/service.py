from datetime import datetime
from time import sleep
from typing import List, Optional, Dict, TYPE_CHECKING
from urllib.parse import urlparse, parse_qsl

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

    def _parse_url_components(self, url: str) -> Dict:
        """Parse URL into components for storage"""
        self.logger.info(f"TESTING_1: {url}")
        parsed = urlparse(url)
        path_parts = [p for p in parsed.path.split('/') if p]

        return {
            'full_url': url,
            'domain': parsed.netloc,
            'path_segments': path_parts,
            'endpoint_type': path_parts[0] if path_parts else None,
            'resource_id': path_parts[1] if len(path_parts) > 1 else None
        }

    def _create_endpoint_record(self, subdomain_id: int, result: 'KatanaResult') -> Endpoint:
        """Create an Endpoint record from a KatanaResult"""
        url_components = self._parse_url_components(result)
        self.logger.info(f"TESTING_2: {result}")

        # Ensure required fields have values
        if not result.url:
            raise ValueError("URL cannot be empty")
        if not url_components['domain']:
            raise ValueError("Domain cannot be empty")

        # Convert path_segments to empty list if None
        if url_components['path_segments'] is None:
            url_components['path_segments'] = []

        # Ensure parameters is a dict
        parameters = result.parameters if result.parameters else {}

        # Create endpoint with validated data
        endpoint = Endpoint(
            subdomain_id=subdomain_id,
            **url_components,  # Unpacks full_url, domain, path_segments, etc.

            # Discovery context
            source_page=result.request.get('source', ''),
            discovery_tag=result.request.get('tag', ''),
            discovery_attribute=result.request.get('attribute', ''),
            discovery_time=datetime.fromisoformat(result.timestamp),

            # Request/Response data
            method=result.method or 'GET',
            content_type=result.content_type,
            status_code=result.status_code,
            response_size=result.response_size,
            parameters=parameters,
            is_authenticated=False,
            additional_info={
                'headers': result.headers or {},
                'response_body': result.response_body
            }
        )

        # Validate required fields
        if not endpoint.full_url or not endpoint.domain:
            raise ValueError(f"Missing required fields for endpoint: {endpoint.__dict__}")

        return endpoint

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

            # Log what we're about to save
            if endpoints:
                self.logger.info(f"Saving {len(endpoints)} endpoints")
                for endpoint in endpoints:
                    self.logger.debug(f"Endpoint: {endpoint.full_url}")
                try:
                    self.session.bulk_save_objects(endpoints)
                except Exception as e:
                    self.logger.error(f"Failed to save endpoints: {str(e)}")
                    raise

            if js_files:
                self.logger.info(f"Saving {len(js_files)} JavaScript files")
                for js in js_files:
                    self.logger.debug(f"JavaScript: {js.url}")
                try:
                    self.session.bulk_save_objects(js_files)
                except Exception as e:
                    self.logger.error(f"Failed to save JavaScript files: {str(e)}")
                    raise

            try:
                self.session.commit()
                self.logger.info("Successfully committed all changes to database")
            except Exception as e:
                self.logger.error(f"Failed to commit changes: {str(e)}")
                self.session.rollback()
                raise

        except Exception as e:
            self.logger.error(f"Error processing results: {str(e)}")
            self.session.rollback()
            raise
