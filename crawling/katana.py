import asyncio
import json
import os
from typing import List, Dict, Optional
from urllib.parse import urlparse
import logging
import shutil
from pathlib import Path

from core.models import KatanaResult

class KatanaCrawler:
    def __init__(self, katana_path: Optional[str] = None):
        """Initialize Katana crawler."""
        self.logger = logging.getLogger(__name__)
        self.katana_path = katana_path or shutil.which("katana")
        if not self.katana_path:
            raise FileNotFoundError("Katana binary not found. Please install katana or specify the path.")
        self._current_process = None
        self._cleanup_lock = asyncio.Lock()
        self._is_closed = False
        
    async def verify_installation(self) -> bool:
        """
        Verify katana installation by running version check.
        Returns True if katana is properly installed and working.
        """
        try:
            # Verify binary exists and is executable
            katana_path = Path(self.katana_path)
            if not katana_path.exists():
                self.logger.error(f"Katana binary not found at: {self.katana_path}")
                return False
            if not os.access(self.katana_path, os.X_OK):
                self.logger.error(f"Katana binary is not executable: {self.katana_path}")
                return False
            
            # Try running version check
            process = await asyncio.create_subprocess_exec(
                self.katana_path,
                "--version",  # Changed to --version as it's more standard
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=10)
                if process.returncode != 0:
                    # Try -version if --version fails
                    process = await asyncio.create_subprocess_exec(
                        self.katana_path,
                        "-version",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=10)
                    if process.returncode != 0:
                        self.logger.error(f"Katana version check failed: {stderr.decode().strip()}")
                        return False
            except asyncio.TimeoutError:
                self.logger.error("Katana version check timed out")
                return False
                
            version = stdout.decode().strip()
            self.logger.info(f"Found katana version: {version}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error verifying katana installation: {str(e)}")
            return False

    async def close(self):
        """Cleanup any running processes."""
        async with self._cleanup_lock:
            if self._is_closed:
                return

            try:
                if self._current_process:
                    self.logger.debug("Terminating running katana process")
                    try:
                        self._current_process.terminate()
                        await asyncio.wait_for(self._current_process.wait(), timeout=5)
                    except asyncio.TimeoutError:
                        self.logger.warning("Katana process did not terminate, killing it")
                        self._current_process.kill()
                    self._current_process = None
                self._is_closed = True
            except Exception as e:
                self.logger.error(f"Error during katana cleanup: {str(e)}")

    async def crawl_all(self, target_url: str, timeout: int = 180) -> List[KatanaResult]:
        """Crawl target URL with simplified configuration."""
        # Verify installation before crawling
        if not await self.verify_installation():
            self.logger.error("Katana installation verification failed")
            return []

        if "://" in target_url:
            domain = target_url.split("://")[1]
        else:
            domain = target_url
            
        self.logger.info(f"Crawling {domain}")
        
        cmd = [
            self.katana_path,
            "-u", f"https://{domain}",
            "-j",      # JSON output
            "-silent", # Reduce noise
            "-d", "5", # Reasonable depth
            "-c", "10" # Reasonable concurrency
        ]
        
        try:
            results = await self._execute_command(cmd, timeout)
            if not results:
                return []
                
            processed_results = [self._parse_result(r, "crawler") for r in results]
            return self._deduplicate_results(processed_results)
            
        except Exception as e:
            self.logger.error(f"Error crawling {domain}: {str(e)}")
            return []

    async def _execute_command(self, cmd: List[str], timeout: int = 60) -> List[Dict]:
        """Execute katana command and parse results."""
        if self._is_closed:
            raise RuntimeError("KatanaCrawler is closed")

        try:
            # Verify katana binary exists and is executable
            katana_path = Path(self.katana_path)
            if not katana_path.exists():
                self.logger.error(f"Katana binary not found at: {self.katana_path}")
                return []
            if not os.access(self.katana_path, os.X_OK):
                self.logger.error(f"Katana binary is not executable: {self.katana_path}")
                return []
                
            # Log the exact command being executed
            cmd_str = ' '.join(cmd)
            self.logger.info(f"Executing katana command: {cmd_str}")
            
            self._current_process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            if not self._current_process:
                self.logger.error("Failed to create katana process")
                return []
                
            self.logger.info(f"Started katana process with PID: {self._current_process.pid}")
            
            process = None
            try:
                process = self._current_process  # Keep reference
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
                returncode = process.returncode if process else None
                
                # Log command output
                stderr_text = stderr.decode().strip()
                if stderr_text:
                    self.logger.warning(f"Katana stderr output:\n{stderr_text}")
                
                stdout_text = stdout.decode().strip()
                if stdout_text:
                    self.logger.debug(f"Katana stdout first 1000 chars:\n{stdout_text[:1000]}")
                else:
                    self.logger.warning("Katana produced no stdout output")
            except asyncio.CancelledError:
                self.logger.warning("Katana command cancelled")
                if process:
                    process.terminate()
                    try:
                        await asyncio.wait_for(process.wait(), timeout=5)
                    except asyncio.TimeoutError:
                        process.kill()
                raise
            finally:
                self._current_process = None  # Clear for cleanup
            
            if returncode is None:
                self.logger.error("Process terminated without returncode")
                return []
            if returncode != 0:
                self.logger.error(f"Katana command failed: {stderr.decode().strip()}")
                return []
            
            results = []
            for line in stdout.decode().splitlines():
                try:
                    if line.strip():
                        results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
                    
            return results
            
        except asyncio.TimeoutError:
            self.logger.error(f"Command timed out after {timeout} seconds")
            return []
        except Exception as e:
            self.logger.error(f"Error executing command: {str(e)}")
            return []

    def _parse_result(self, result: Dict, source: str) -> KatanaResult:
        """Parse raw katana result."""
        parsed_url = urlparse(result.get('url', ''))
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

    def _deduplicate_results(self, results: List[KatanaResult]) -> List[KatanaResult]:
        """Remove duplicate results."""
        seen = set()
        unique_results = []
        
        for result in results:
            key = (result.url, result.method)
            if key not in seen:
                seen.add(key)
                unique_results.append(result)
        
        return unique_results
