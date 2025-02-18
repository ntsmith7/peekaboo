import asyncio
import json
import os
from datetime import datetime
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qsl
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
        """Verify katana installation by running version check."""
        try:
            # Verify binary exists and is executable
            katana_path = Path(self.katana_path)
            if not katana_path.exists():
                self.logger.error(f"Katana binary not found at: {self.katana_path}")
                return False
            if not os.access(self.katana_path, os.X_OK):
                self.logger.error(f"Katana binary is not executable: {self.katana_path}")
                return False
            
            # Simple existence check is sufficient since we already verified executable permissions
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
                    self._current_process.terminate()
                    try:
                        await asyncio.wait_for(self._current_process.wait(), timeout=5)
                    except asyncio.TimeoutError:
                        self._current_process.kill()
                    self._current_process = None
                self._is_closed = True
            except Exception as e:
                self.logger.error(f"Error during katana cleanup: {str(e)}")

    async def crawl_all(self, target_url: str, timeout: int = 180) -> List[KatanaResult]:
        """Crawl target URL with simplified configuration."""
        if not await self.verify_installation():
            self.logger.error("Katana installation verification failed")
            return []

        if "://" in target_url:
            domain = target_url.split("://")[1]
        else:
            domain = target_url
            
        cmd = [
            self.katana_path,
            "-u", f"https://{domain}",
            "-j"  # JSON output
        ]
        
        try:
            stdout = await self._execute_command(cmd, timeout)
            if not stdout:
                return []
                
            results = self._parse_json_lines(stdout)
            return [self._parse_result(r) for r in results]
            
        except Exception as e:
            self.logger.error(f"Error crawling {domain}: {str(e)}")
            return []

    async def _execute_command(self, cmd: List[str], timeout: int = 60) -> Optional[str]:
        """Execute katana command and return stdout."""
        if self._is_closed:
            raise RuntimeError("KatanaCrawler is closed")

        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            self._current_process = process
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            if stderr:
                stderr_text = stderr.decode().strip()
                if stderr_text:  # Only log if there's actual content
                    self.logger.warning(f"Katana stderr output:\n{stderr_text}")
            
            if process.returncode != 0:
                self.logger.error(f"Katana command failed with code {process.returncode}")
                return None
                
            return stdout.decode() if stdout else None
            
        except asyncio.TimeoutError:
            self.logger.error(f"Command timed out after {timeout} seconds")
            if process:
                process.kill()
            return None
        except Exception as e:
            self.logger.error(f"Error executing command: {str(e)}")
            if process:
                process.kill()
            return None
        finally:
            self._current_process = None

    def _parse_json_lines(self, stdout: str) -> List[Dict]:
        """Parse JSON lines from stdout."""
        results = []
        for line in stdout.splitlines():
            if not line.strip():
                continue
                
            try:
                result = json.loads(line)
                results.append(result)
            except json.JSONDecodeError as e:
                self.logger.error(f"Failed to parse JSON line: {str(e)}")
                continue
                
        return results

    def _parse_result(self, result: Dict) -> KatanaResult:
        """Parse raw katana result into KatanaResult object."""
        endpoint = result.get('endpoint', '')
        parsed_url = urlparse(endpoint)
        self.logger.debug(f"parsed_url11111: {parsed_url}")   
        
        # Extract query parameters
        parameters = {}
        if parsed_url.query:
            parameters['query'] = dict(parse_qsl(parsed_url.query))
        if result.get('form_data'):
            parameters['form_data'] = result.get('form_data')

        return KatanaResult(
            timestamp=result.get('timestamp', datetime.utcnow().isoformat()),
            url=endpoint,
            method=result.get('method', 'GET'),
            tag=result.get('tag', ''),
            attribute=result.get('attribute', ''),
            source=result.get('source', ''),
            status_code=result.get('status-code'),
            content_type=result.get('content-type'),
            response_size=result.get('response-size'),
            parameters=parameters,
            headers=result.get('headers', {}),
            response_body=result.get('response', '')
        )
