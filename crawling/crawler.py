import asyncio
import logging
import os
import shutil
from pathlib import Path
from typing import List, Optional

class KatanaCrawler:
    """Handles direct interaction with katana binary."""
    
    def __init__(self, katana_path: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        self.katana_path = katana_path or shutil.which("katana")
        if not self.katana_path:
            raise FileNotFoundError("Katana binary not found. Please install katana or specify the path.")
        self._current_process = None
        self._cleanup_lock = asyncio.Lock()
        self._is_closed = False

    async def verify_installation(self) -> bool:
        """Verify katana installation and binary permissions."""
        try:
            katana_path = Path(self.katana_path)
            if not katana_path.exists():
                self.logger.error(f"Katana binary not found at: {self.katana_path}")
                return False
            if not os.access(self.katana_path, os.X_OK):
                self.logger.error(f"Katana binary is not executable: {self.katana_path}")
                return False
            return True
        except Exception as e:
            self.logger.error(f"Error verifying katana installation: {str(e)}")
            return False

    async def crawl(self, target_url: str, timeout: int = 180) -> Optional[str]:
        """Execute katana crawl and return raw output."""
        if not await self.verify_installation():
            return None

        cmd = self._build_command(target_url)
        
        try:
            return await self._execute_command(cmd, timeout)
        except Exception as e:
            self.logger.error(f"Crawl failed: {str(e)}")
            return None

    def _build_command(self, target_url: str) -> List[str]:
        """Build katana command with proper arguments."""
        domain = target_url.split("://")[1] if "://" in target_url else target_url
        return [
            self.katana_path,
            "-u", f"https://{domain}",
            "-j",  # JSON output
            "-silent",  # Reduce noise
            "-rl", "10",  # Rate limit
            "-timeout", "30"  # Timeout per request
        ]

    async def _execute_command(self, cmd: List[str], timeout: int) -> Optional[str]:
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
                if stderr_text:
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
