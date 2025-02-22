import asyncio
import json
from typing import List
from infrastructure.logging_config import get_logger

class SubdomainScanner:
    """Handles passive subdomain discovery using external tools"""
    
    def __init__(self, rate_limit: int = 5):
        self.rate_limit = rate_limit
        self.logger = get_logger(__name__)

    async def scan(self, target: str) -> List[str]:
        """
        Perform passive subdomain scanning using subfinder.
        Returns a list of discovered subdomains.
        """
        cmd = [
            'subfinder',
            '-d', target,
            '-silent',
            '-json',
            '-timeout', '30'
        ]
        
        if self.rate_limit:
            cmd.extend(['-rate-limit', str(self.rate_limit)])

        try:
            self.logger.info(f"Starting passive scan for {target}")
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=300  # 5 minute timeout
            )

            if process.returncode != 0:
                self.logger.error(f"Subfinder failed: {stderr.decode()}")
                return []

            results = []
            for line in stdout.decode().splitlines():
                try:
                    if line.strip():
                        data = json.loads(line)
                        results.append(data['host'])
                except json.JSONDecodeError:
                    self.logger.warning(f"Failed to parse JSON line: {line}")
                except KeyError:
                    self.logger.warning(f"Missing 'host' key in JSON data: {line}")
                except Exception as e:
                    self.logger.warning(f"Error processing result: {str(e)}")

            self.logger.info(f"Scan completed. Found {len(results)} subdomains")
            return results

        except asyncio.TimeoutError:
            self.logger.error(f"Scan timed out for {target}")
            return []
        except Exception as e:
            self.logger.error(f"Scan error: {str(e)}")
            return []
