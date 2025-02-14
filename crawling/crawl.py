from typing import Optional, List, Dict
import logging
import asyncio
from datetime import datetime
from urllib.parse import urlparse

from .katana import KatanaCrawler, KatanaResult
from core.models import Endpoint, JavaScript, EndpointSource
from infrastrucutre.database import DatabaseManager

db_manager = DatabaseManager()

class Crawler:
    def __init__(self, subdomain_id: int):
        self.subdomain_id = subdomain_id
        self.logger = logging.getLogger(__name__)
        self.katana = KatanaCrawler()
        self.session = db_manager.get_session()

    async def start_crawl(self, target_url: str, is_authenticated: bool = False) -> None:
        """
        Start crawling process for a target URL
        """
        self.logger.info(f"Starting crawl for {target_url}")
        try:
            results = await self.katana.crawl_all(target_url)
            await self._process_results(results, is_authenticated)
            
        except Exception as e:
            self.logger.error(f"Error during crawl: {str(e)}", exc_info=True)
            raise
        finally:
            self.session.close()

    async def _process_results(self, results: List[KatanaResult], is_authenticated: bool) -> None:
        """
        Process and store crawl results
        """
        try:
            endpoints = []
            js_files = []

            for result in results:
                if result.url.endswith('.js'):
                    try:
                        js_files.append(self._create_js_file(result))
                        self.logger.debug(f"Created JavaScript record for: {result.url}")
                    except Exception as e:
                        self.logger.error(f"Error processing JavaScript file {result.url}: {str(e)}")
                        continue
                else:
                    try:
                        endpoints.append(self._create_endpoint(result, is_authenticated))
                        self.logger.debug(f"Created endpoint record for: {result.url}")
                    except Exception as e:
                        self.logger.error(f"Error processing endpoint {result.url}: {str(e)}")
                        continue

            # Log what we're about to save
            if endpoints:
                self.logger.info(f"Saving {len(endpoints)} endpoints")
                for endpoint in endpoints:
                    self.logger.debug(f"Endpoint: {endpoint.full_url}")
                try:
                    self.session.bulk_save_objects(endpoints)
                    self.logger.info("Successfully saved endpoints")
                except Exception as e:
                    self.logger.error(f"Failed to save endpoints: {str(e)}")
                    raise

            if js_files:
                self.logger.info(f"Saving {len(js_files)} JavaScript files")
                for js in js_files:
                    self.logger.debug(f"JavaScript: {js.url}")
                try:
                    self.session.bulk_save_objects(js_files)
                    self.logger.info("Successfully saved JavaScript files")
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

    def _parse_url_components(self, url: str) -> Dict:
        """Parse URL into components for storage"""
        parsed = urlparse(url)
        path_parts = [p for p in parsed.path.split('/') if p]
        
        return {
            'full_url': url,
            'domain': parsed.netloc,
            'path_segments': path_parts,
            'endpoint_type': path_parts[0] if path_parts else None,
            'resource_id': path_parts[1] if len(path_parts) > 1 else None
        }

    def _create_endpoint(self, result: KatanaResult, is_authenticated: bool) -> Endpoint:
        """Create Endpoint record from a KatanaResult"""
        try:
            url_components = self._parse_url_components(result.url)
            self.logger.debug(f"Creating endpoint record for URL: {result.url}")
            
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
                subdomain_id=self.subdomain_id,
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
                is_authenticated=is_authenticated,
                additional_info={
                    'headers': result.headers or {},
                    'response_body': result.response_body
                }
            )
            
            # Validate required fields
            if not endpoint.full_url or not endpoint.domain:
                raise ValueError(f"Missing required fields for endpoint: {endpoint.__dict__}")
                
            return endpoint
        except Exception as e:
            self.logger.error(f"Error creating endpoint: {str(e)}")
            raise

    def _create_js_file(self, result: KatanaResult) -> JavaScript:
        """Create JavaScript record from a KatanaResult"""
        try:
            if not result.url:
                raise ValueError("URL cannot be empty")
                
            return JavaScript(
                subdomain_id=self.subdomain_id,
                url=result.url,
                file_hash=None,  # TODO: Calculate hash from response body
                endpoints_referenced=[],
                variables={},
                discovery_time=datetime.fromisoformat(result.timestamp),
                last_modified=None  # TODO: Extract from headers if available
            )
        except Exception as e:
            self.logger.error(f"Error creating JavaScript file: {str(e)}")
            raise

    def _map_source(self, katana_source: str) -> EndpointSource:
        """
        Map Katana source to EndpointSource enum
        """
        source_mapping = {
            'crawler': EndpointSource.CRAWL,
            'javascript_parser': EndpointSource.JS_PARSE,
            'form_submission': EndpointSource.FORM,
            'custom': EndpointSource.CRAWL
        }
        return source_mapping.get(katana_source, EndpointSource.CRAWL)
