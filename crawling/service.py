import asyncio
import logging
from datetime import datetime
from typing import List, Dict, Optional
from urllib.parse import urlparse

from core.models import Subdomain, Endpoint, JavaScript, KatanaResult
from infrastructure.database import DatabaseSession
from .crawler import KatanaCrawler
from .parser import KatanaParser
from .js_analyzer import JavaScriptAnalyzer

class CrawlingService:
    """Orchestrates crawling operations."""
    
    def __init__(self, db_session: DatabaseSession):
        """Initialize the crawling service."""
        self.session = db_session
        self.logger = logging.getLogger(__name__)
        self.crawler = KatanaCrawler()
        self.parser = KatanaParser()
        self.js_analyzer = JavaScriptAnalyzer()
        self.max_concurrent_crawls = 5
        self.crawl_semaphore = asyncio.Semaphore(self.max_concurrent_crawls)
        self._cleanup_lock = asyncio.Lock()
        self._is_closed = False

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()

    async def close(self):
        """Cleanup resources."""
        async with self._cleanup_lock:
            if self._is_closed:
                return
            try:
                if hasattr(self, 'crawler'):
                    await self.crawler.close()
                self._is_closed = True
            except Exception as e:
                self.logger.error(f"Error during cleanup: {str(e)}")

    async def crawl_specific_targets(self, subdomain_ids: List[int]):
        """Crawl specific subdomains by their IDs."""
        try:
            subdomains = self.session.session.query(Subdomain).filter(
                Subdomain.id.in_(subdomain_ids)
            ).all()

            if not subdomains:
                self.logger.warning("No subdomains found for the given IDs")
                return

            tasks = [self._crawl_subdomain(sub) for sub in subdomains]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            success_count = sum(1 for r in results if not isinstance(r, Exception))
            self.logger.info(f"Completed crawling {success_count}/{len(tasks)} subdomains")

        except Exception as e:
            self.logger.error(f"Error in crawl_specific_targets: {str(e)}")
            raise

    async def _crawl_subdomain(self, subdomain: Subdomain):
        """Crawl a single subdomain."""
        async with self.crawl_semaphore:
            url = f"https://{subdomain.domain}"
            
            try:
                # Get raw output from crawler
                raw_output = await self.crawler.crawl(url, timeout=180)
                if not raw_output:
                    return
                
                # Parse results
                results = self.parser.parse_output(raw_output)
                if not results:
                    return
                
                # Process and store results
                await self._process_results(subdomain.id, results)
                
                # Update subdomain
                subdomain.last_checked = datetime.utcnow()
                self.session.session.commit()
                
            except Exception as e:
                self.logger.error(f"Error crawling {url}: {str(e)}")
                raise

    async def _process_results(self, subdomain_id: int, results: List[KatanaResult]):
        """Process and store crawl results."""
        try:
            endpoints = []
            js_files = []

            # Process non-JS files first
            for result in results:
                if not result.url.endswith('.js'):
                    endpoints.append(self._create_endpoint_record(subdomain_id, result))

            # Process JS files concurrently
            js_tasks = [
                self._create_js_record(subdomain_id, result)
                for result in results
                if result.url.endswith('.js')
            ]
            if js_tasks:
                js_results = await asyncio.gather(*js_tasks, return_exceptions=True)
                for js_result in js_results:
                    if isinstance(js_result, Exception):
                        self.logger.error(f"Error processing JS file: {str(js_result)}")
                    elif js_result:  # Skip None results
                        js_files.append(js_result)

            if endpoints:
                self.logger.info(f"Saving {len(endpoints)} endpoints")
                self.session.session.add_all(endpoints)

            if js_files:
                self.logger.info(f"Saving {len(js_files)} JavaScript files")
                self.session.session.add_all(js_files)

            try:
                self.session.session.commit()
            except Exception as e:
                self.logger.error(f"Error saving to database: {str(e)}")
                self.session.session.rollback()
                raise

        except Exception as e:
            self.logger.error(f"Error processing results: {str(e)}")
            self.session.session.rollback()
            raise

    def _create_endpoint_record(self, subdomain_id: int, result: KatanaResult) -> Endpoint:
        """Create an Endpoint record from a KatanaResult."""
        if not result.url:
            raise ValueError("url cannot be None")
        
        parsed = urlparse(result.url)
        if not parsed.netloc:
            raise ValueError("domain cannot be None")
            
        path_segments = [p for p in parsed.path.split('/') if p]

        # Create endpoint with validated fields
        endpoint = Endpoint(
            subdomain_id=subdomain_id,
            full_url=result.url or '',  # nullable=False
            domain=parsed.netloc or '',  # nullable=False
            path_segments=path_segments or [],  # JSON field
            endpoint_type=path_segments[0] if path_segments else '',  # String field
            resource_id=path_segments[1] if len(path_segments) > 1 else '',  # String field
            source_page=result.source or '',  # String field
            discovery_tag=result.tag or '',  # String field
            discovery_attribute=result.attribute or '',  # String field
            discovery_time=datetime.fromisoformat(result.timestamp),  # Has default
            method=result.method or 'GET',  # String field
            status_code=result.status_code or 0,  # Integer field
            content_type=result.content_type or '',  # String field
            response_size=result.response_size or 0,  # Integer field
            parameters=result.parameters or {},  # JSON field
            is_authenticated=False,  # Boolean field
            additional_info={'headers': result.headers or {}}  # JSON field
        )
        
        # Log the created endpoint for debugging
        self.logger.debug(f"Created endpoint record: subdomain_id={subdomain_id}, url={result.url}")
        
        return endpoint

    async def _create_js_record(self, subdomain_id: int, result: KatanaResult) -> Optional[JavaScript]:
        """Create a JavaScript record from a KatanaResult."""
        if not result.url:
            raise ValueError("url cannot be None")
            
        # Use response_body directly
        if not result.response_body:
            self.logger.warning(f"No JS content in response body from {result.url}")
            return None
            
        # Analyze JS content
        try:
            # First analyze the content
            analysis_result = self.js_analyzer.analyze(
                content=result.response_body,
                source_url=result.url
            )
            
            # Then create the models from the analysis
            js_file, endpoints = self.js_analyzer.create_models(
                analysis_result=analysis_result,
                subdomain_id=subdomain_id
            )
            
            # Store discovered endpoints
            if endpoints:
                self.logger.info(f"Found {len(endpoints)} endpoints in {result.url}")
                self.session.session.add_all(endpoints)
                
            return js_file
            
        except Exception as e:
            self.logger.error(f"Error analyzing JS from {result.url}: {str(e)}")
            return None
