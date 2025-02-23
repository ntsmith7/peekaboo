import json
import logging
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qsl

from core.models import KatanaResult

class KatanaParser:
    """Handles parsing of katana output into structured data."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def parse_output(self, raw_output: str) -> List[KatanaResult]:
        """Parse raw katana output into KatanaResult objects."""
        if not raw_output:
            return []

        json_results = self._parse_json_lines(raw_output)
        return [self._create_result(result) for result in json_results]

    def _parse_json_lines(self, output: str) -> List[Dict]:
        """Parse JSON lines from raw output."""
        results = []
        for line in output.splitlines():
            if not line.strip():
                continue
                
            try:
                result = json.loads(line)
                results.append(result)
            except json.JSONDecodeError as e:
                self.logger.error(f"JSON parse error: {str(e)}")
                continue
        return results

    def _create_result(self, json_data: Dict) -> KatanaResult:
        """Create a KatanaResult from parsed JSON data."""
        request = json_data.get('request', {})
        response = json_data.get('response', {})
        
        # URL parsing and parameter extraction
        url_data = self._parse_url(request.get('endpoint', ''))
        
        return KatanaResult(
            timestamp=json_data.get('timestamp', datetime.utcnow().isoformat()),
            url=url_data['url'],
            method=request.get('method', 'GET'),
            tag=request.get('tag', ''),
            attribute=request.get('attribute', ''),
            source=request.get('source', ''),
            status_code=response.get('status_code'),
            content_type=response.get('headers', {}).get('content-type'),
            response_size=response.get('content_length'),
            parameters=url_data['parameters'],
            headers=response.get('headers', {}),
            response_body=response.get('body', '')
        )

    def _parse_url(self, url: str) -> Dict:
        """
        Parse URL into components including parameters.
        Handles both query parameters and URL structure.
        """
        if not url:
            return {'url': '', 'parameters': {}}

        parsed = urlparse(url)
        parameters = {}

        # Extract query parameters
        if parsed.query:
            parameters['query'] = dict(parse_qsl(parsed.query))

        # Extract path parameters (if needed)
        path_segments = [seg for seg in parsed.path.split('/') if seg]
        if path_segments:
            parameters['path'] = path_segments

        return {
            'url': url,
            'parameters': parameters
        }