import asyncio
from dataclasses import dataclass
import json
from typing import List, Dict, Optional, Set
from urllib.parse import urlparse
import logging
from pathlib import Path

@dataclass
class KatanaResult:
    url: str
    method: str
    status_code: Optional[int]
    content_type: Optional[str]
    response_size: Optional[int]
    parameters: Dict
    headers: Dict
    response_body: Optional[str]
    source: str

class KatanaCrawler:
    def __init__(self, katana_path: str = "katana"):
        """
        Initialize Katana crawler with path to binary and logger
        """
        self.katana_path = katana_path
        self.logger = logging.getLogger(__name__)
        self._validate_installation()

    def _validate_installation(self):
        """Validate katana installation"""
        katana_path = Path(self.katana_path)
        if not katana_path.exists():
            self.logger.error(f"Katana binary not found at {self.katana_path}")
            raise FileNotFoundError(f"Katana binary not found at {self.katana_path}")

    async def crawl_all(self, target_url: str) -> List[KatanaResult]:
        """
        Perform all types of crawling concurrently and return combined results
        """
        self.logger.info(f"Starting comprehensive crawl of {target_url}")
        
        tasks = [
            self.crawl_endpoints(target_url),
            self.crawl_js(target_url),
            self.crawl_forms(target_url)
        ]
        
        results = []
        for completed_task in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(completed_task, Exception):
                self.logger.error(f"Crawl task failed: {str(completed_task)}")
                continue
            results.extend(completed_task)
        
        self.logger.info(f"Comprehensive crawl completed. Found {len(results)} unique endpoints")
        return self._deduplicate_results(results)

    async def crawl_endpoints(self, target_url: str) -> List[KatanaResult]:
        """
        Standard crawl optimized for endpoint discovery
        """
        self.logger.debug(f"Starting endpoint crawl for {target_url}")
        cmd = [
            self.katana_path,
            "-u", target_url,
            "-d", "3",
            "-rl", "150",
            "-c", "10",
            "-j",
            "-silent",
            "-xhr"
        ]
        
        results = await self._execute_command(cmd)
        processed_results = [self._parse_result(r, "crawler") for r in results]
        self.logger.debug(f"Endpoint crawl completed. Found {len(processed_results)} results")
        return processed_results

    async def crawl_js(self, target_url: str) -> List[KatanaResult]:
        """
        JavaScript-focused crawl
        """
        self.logger.debug(f"Starting JavaScript crawl for {target_url}")
        cmd = [
            self.katana_path,
            "-u", target_url,
            "-jc",
            "-jsl",
            "-d", "4",
            "-j",
            "-silent"
        ]
        
        results = await self._execute_command(cmd)
        processed_results = [self._parse_result(r, "javascript_parser") for r in results]
        self.logger.debug(f"JavaScript crawl completed. Found {len(processed_results)} results")
        return processed_results

    async def crawl_forms(self, target_url: str) -> List[KatanaResult]:
        """
        Form-focused crawl
        """
        self.logger.debug(f"Starting form crawl for {target_url}")
        cmd = [
            self.katana_path,
            "-u", target_url,
            "-aff",
            "-fx",
            "-d", "3",
            "-j",
            "-silent"
        ]
        
        results = await self._execute_command(cmd)
        processed_results = [self._parse_result(r, "form_submission") for r in results]
        self.logger.debug(f"Form crawl completed. Found {len(processed_results)} results")
        return processed_results

    async def custom_crawl(self, target_url: str, **kwargs) -> List[KatanaResult]:
        """
        Custom crawl with user-defined parameters
        """
        self.logger.debug(f"Starting custom crawl for {target_url} with params: {kwargs}")
        cmd = [self.katana_path, "-u", target_url, "-silent", "-j"]
        
        flag_mapping = {
            "depth": "-d",
            "concurrency": "-c",
            "rate_limit": "-rl",
            "timeout": "-timeout",
            "delay": "-rd",
            "js_crawl": "-jc",
            "headless": "-hl",
            "form_fill": "-aff"
        }
        
        for key, value in kwargs.items():
            if key in flag_mapping:
                if isinstance(value, bool) and value:
                    cmd.append(flag_mapping[key])
                else:
                    cmd.extend([flag_mapping[key], str(value)])
        
        results = await self._execute_command(cmd)
        processed_results = [self._parse_result(r, "custom") for r in results]
        self.logger.debug(f"Custom crawl completed. Found {len(processed_results)} results")
        return processed_results

    async def _execute_command(self, cmd: List[str]) -> List[Dict]:
        """Execute katana command asynchronously and return parsed JSON results"""
        try:
            self.logger.debug(f"Executing command: {' '.join(cmd)}")
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                error_msg = stderr.decode()
                self.logger.error(f"Katana command failed: {error_msg}")
                raise RuntimeError(f"Katana command failed: {error_msg}")
            
            results = []
            for line in stdout.decode().splitlines():
                try:
                    if line.strip():
                        result = json.loads(line)
                        results.append(result)
                except json.JSONDecodeError as e:
                    self.logger.warning(f"Failed to parse JSON line: {e}")
                    continue
                    
            return results
            
        except Exception as e:
            self.logger.error(f"Error executing katana: {str(e)}")
            raise

    def _parse_result(self, result: Dict, source: str) -> KatanaResult:
        """Convert raw katana result to KatanaResult object"""
        try:
            parsed_url = urlparse(result.get('url', ''))
            
            return KatanaResult(
                url=result.get('url', ''),
                method=result.get('method', 'GET'),
                status_code=result.get('status-code'),
                content_type=result.get('content-type'),
                response_size=result.get('response-size'),
                parameters={
                    'query': parsed_url.query,
                    'form_data': result.get('form_data', {})
                },
                headers=result.get('headers', {}),
                response_body=result.get('response', None),
                source=source
            )
        except Exception as e:
            self.logger.error(f"Error parsing result: {str(e)}")
            raise

    def _deduplicate_results(self, results: List[KatanaResult]) -> List[KatanaResult]:
        """Remove duplicate results based on URL and method"""
        seen = set()
        unique_results = []
        
        for result in results:
            key = (result.url, result.method)
            if key not in seen:
                seen.add(key)
                unique_results.append(result)
        
        return unique_results