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
        endpoints = []
        js_files = []

        for result in results:
            if result.url.endswith('.js'):
                js_files.append(self._create_js_file(result))
            else:
                try:
                    endpoints.append(self._create_endpoint(result, is_authenticated))
                except Exception as e:
                    self.logger.error(f"Error processing endpoint {result.url}: {str(e)}")
                    continue

        if endpoints:
            self.session.bulk_save_objects(endpoints)
        if js_files:
            self.session.bulk_save_objects(js_files)

        try:
            self.session.commit()
        except Exception as e:
            self.logger.error(f"Error saving results: {str(e)}")
            self.session.rollback()
            raise

    def _create_endpoint(self, result: KatanaResult, is_authenticated: bool) -> Endpoint:
        """
        Create Endpoint object from crawl result
        """
        try:
            parsed_url = urlparse(result.url)
            
            # Ensure parameters is a dict
            parameters = result.parameters if isinstance(result.parameters, dict) else {}
            
            return Endpoint(
                subdomain_id=self.subdomain_id,
                path=parsed_url.path,
                method=result.method,
                source=self._map_source(result.source),
                discovery_time=datetime.utcnow(),
                content_type=result.content_type,
                status_code=result.status_code,
                response_size=result.response_size,
                parameters=parameters,
                is_authenticated=is_authenticated,
                additional_info={
                    'query_string': parsed_url.query,
                    'headers': result.headers if result.headers else {}
                }
            )
        except Exception as e:
            self.logger.error(f"Error creating endpoint: {str(e)}")
            raise

    def _create_js_file(self, result: KatanaResult) -> JavaScript:
        """
        Create JavaScript object from crawl result
        """
        try:
            return JavaScript(
                subdomain_id=self.subdomain_id,
                url=result.url,
                endpoints_referenced=[],
                variables={},
                discovery_time=datetime.utcnow(),
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
