import asyncio
import json
import logging
import uuid
from typing import List


class Subfinder:
    def __init__(self, target: str):
        self.id = uuid.uuid4()
        self.target = target
        self.global_limit = None
        self.output_file = None
        self.output_json = False
        self.logger = logging.getLogger(f'subfinder.{self.id}')
        self.logger.debug(f"Initialized Subfinder for target: {target}")

    def set_rate_limits(self, global_limit: int):
        self.logger.debug(f"Setting rate limit to: {global_limit}")
        self.global_limit = global_limit
        return self

    def set_output(self, output_file: str, json: bool = False):
        self.logger.debug(f"Setting output file to: {output_file} (JSON: {json})")
        self.output_file = output_file
        self.output_json = json
        return self

    async def run(self) -> List[str]:
        """
        Run subfinder against target domain and return discovered subdomains.

        Returns:
            List of discovered subdomains

        Raises:
            Exception: If subfinder execution fails
        """
        self.logger.info(f"Starting subfinder scan for: {self.target}")
        
        cmd = [
            'subfinder',
            '-d', self.target,
            '-silent',  # Minimize output
            '-json'  # JSON output for reliable parsing
        ]

        if self.global_limit:
            cmd.extend(['-rate-limit', str(self.global_limit)])


        self.logger.debug(f"Executing command: {' '.join(cmd)}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                error_msg = stderr.decode()
                self.logger.error(f"Subfinder execution failed: {error_msg}")
                raise Exception(f"Subfinder failed: {error_msg}")

            # Parse JSON output line by line
            subdomains = []
            stdout_text = stdout.decode()
            self.logger.debug(f"Raw subfinder output: {stdout_text}")

            for line in stdout_text.splitlines():
                try:
                    data = json.loads(line)
                    subdomains.append(data['host'])
                except json.JSONDecodeError:
                    self.logger.warning(f"Failed to parse JSON line: {line}")
                    continue
                except KeyError:
                    self.logger.warning(f"Missing 'host' key in JSON data: {line}")
                    continue

            self.logger.info(f"Successfully discovered {len(subdomains)} subdomains")
            return subdomains

        except FileNotFoundError:
            self.logger.error("Subfinder binary not found in system PATH")
            raise Exception("Subfinder binary not found")
        except Exception as e:
            self.logger.error(f"Unexpected error during subfinder execution: {str(e)}")
            raise
