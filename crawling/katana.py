import asyncio
import json
from typing import List, Dict, Optional, Set
from urllib.parse import urlparse
import logging
from pathlib import Path

from core.models import KatanaResult

class KatanaCrawler:
    def __init__(self, katana_path: str = "/usr/local/bin/katana"):
        """
        Initialize Katana crawler with path to binary and logger.
        The binary should be installed in /usr/local/bin/katana
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

    async def crawl_all(self, target_url: str, timeout: int = 180) -> List[KatanaResult]:
        """
        Perform all types of crawling concurrently and return combined results
        
        Args:
            target_url: The URL to crawl
            timeout: Maximum time in seconds for all crawls to complete (default 3 minutes)
        """
        start_time = asyncio.get_event_loop().time()
        self.logger.info(f"Starting comprehensive crawl of {target_url}")
        
        tasks = {
            'endpoints': self.crawl_endpoints(target_url),
            'javascript': self.crawl_js(target_url),
            'forms': self.crawl_forms(target_url)
        }
        
        results = []
        try:
            # Run all crawls with overall timeout
            completed_tasks = await asyncio.wait_for(
                asyncio.gather(*tasks.values(), return_exceptions=True),
                timeout=timeout
            )
            
            for task_name, task_result in zip(tasks.keys(), completed_tasks):
                if isinstance(task_result, Exception):
                    self.logger.error(f"{task_name} crawl failed: {str(task_result)}")
                    continue
                if task_result:  # Check for empty results
                    results.extend(task_result)
                    self.logger.info(f"{task_name.capitalize()} crawl found {len(task_result)} results")
                else:
                    self.logger.warning(f"{task_name.capitalize()} crawl returned no results")
                    
        except asyncio.TimeoutError:
            self.logger.error(f"Comprehensive crawl timed out after {timeout} seconds")
            return []
        except Exception as e:
            self.logger.error(f"Unexpected error during comprehensive crawl: {str(e)}", exc_info=True)
            return []
        
        unique_results = self._deduplicate_results(results)
        duration = asyncio.get_event_loop().time() - start_time
        
        # Calculate statistics
        js_files = sum(1 for r in unique_results if r.url.endswith('.js'))
        forms = sum(1 for r in unique_results if r.source == 'form_submission')
        endpoints = len(unique_results) - js_files - forms
        
        self.logger.info(f"""
Comprehensive crawl completed in {duration:.1f} seconds:
- Total Unique URLs: {len(unique_results)}
- Endpoints: {endpoints}
- JavaScript Files: {js_files}
- Forms: {forms}
- Processing Rate: {len(results)/duration:.1f} URLs/second
        """.strip())
        
        return unique_results

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
            "-xhr",
            "-hl",  # Use headless chrome for better JS support
            "-kf",  # Keep files for debugging
            "-dr",  # Don't print colors
            "-nc",  # Don't use colors
            "-timeout", "30",  # 30 second timeout per request
            "-retry", "2",  # Retry failed requests
            "-sf"  # Skip failed URLs
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
            "-jc",  # Enable JavaScript crawling
            "-jsl",  # Enable JavaScript library crawling
            "-d", "3",  # Reduce depth to prevent hanging
            "-j",  # JSON output
            "-silent",
            "-hl",  # Use headless chrome
            "-kf",  # Keep files
            "-dr",  # Don't print colors
            "-nc",  # Don't use colors
            "-timeout", "30",
            "-retry", "2",
            "-sf"  # Skip failed URLs
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
            "-aff",  # Auto form fill
            "-fx",  # Extract forms
            "-d", "3",
            "-j",
            "-silent",
            "-hl",  # Use headless chrome
            "-kf",  # Keep files
            "-dr",  # Don't print colors
            "-nc",  # Don't use colors
            "-timeout", "30",
            "-retry", "2",
            "-sf"  # Skip failed URLs
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

    async def _execute_command(self, cmd: List[str], timeout: int = 60) -> List[Dict]:
        """
        Execute katana command asynchronously and return parsed JSON results
        
        Args:
            cmd: Command and arguments to execute
            timeout: Maximum time in seconds for command execution (default 60 seconds)
        """
        try:
            start_time = asyncio.get_event_loop().time()
            self.logger.debug(f"Executing command: {' '.join(cmd)}")
            
            # Create and start process
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                # Wait for process with timeout
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                self.logger.error(f"Katana command timed out after {timeout} seconds")
                return []
            
            if process.returncode != 0:
                error_msg = stderr.decode()
                self.logger.error(f"Katana command failed: {error_msg}")
                return []
            
            results = []
            lines = stdout.decode().splitlines()
            total_lines = len(lines)
            
            if not total_lines:
                self.logger.warning("Katana command produced no output")
                return []
                
            self.logger.info(f"Processing {total_lines} Katana results")
            
            for i, line in enumerate(lines, 1):
                if i % 50 == 0:  # Log progress every 50 results
                    self.logger.info(f"Processing Katana output: {i}/{total_lines} ({i/total_lines*100:.1f}%)")
                try:
                    if line.strip():
                        result = json.loads(line)
                        results.append(result)
                except json.JSONDecodeError as e:
                    self.logger.warning(f"Failed to parse JSON line: {e}")
                    continue
            
            duration = asyncio.get_event_loop().time() - start_time
            self.logger.info(f"Katana execution completed in {duration:.1f} seconds")
            
            if not results:
                self.logger.warning("No valid results parsed from Katana output")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error executing katana: {str(e)}")
            raise

    def _parse_result(self, result: Dict, source: str) -> KatanaResult:
        """Convert raw katana result to KatanaResult object"""
        try:
            parsed_url = urlparse(result.get('url', ''))
            
            # Ensure all fields are properly formatted
            parameters = {
                'query': parsed_url.query,
                'form_data': result.get('form_data', {})
            } if result.get('form_data') or parsed_url.query else {}

            return KatanaResult(
                url=result.get('url', ''),
                method=result.get('method', 'GET'),
                status_code=result.get('status-code'),
                content_type=result.get('content-type'),
                response_size=result.get('response-size'),
                parameters=parameters,
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
