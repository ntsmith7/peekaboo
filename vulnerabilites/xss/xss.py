from enum import Enum
from typing import List, Dict, Optional
from dataclasses import dataclass
from datetime import datetime
import logging
import aiohttp
import asyncio

from core.models import Endpoint, Subdomain

# Simple enum for XSS contexts
class XSSContext(Enum):
    HTML = "html"
    SCRIPT = "script"
    ATTRIBUTE = "attribute"
    UNKNOWN = "unknown"

# Basic finding model
@dataclass
class XSSFinding:
    """Represents a discovered XSS vulnerability"""
    endpoint_url: str
    endpoint_id: int
    parameter: str
    payload: str
    proof: str
    severity: str
    discovery_time: datetime = None
    
    def __post_init__(self):
        if self.discovery_time is None:
            self.discovery_time = datetime.utcnow()

# Core XSS Scanner
class XSSScanner:
    """Simple XSS scanner for the first iteration"""
    
    def __init__(self, db_session):
        self.session = db_session
        self.logger = logging.getLogger(__name__)
        self._http_session = None
        
        # Basic set of XSS payloads to start with
        self.payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '"><img src=x onerror=alert(1)>',
            "';alert(1)//"
        ]
        
        # Simple configuration
        self.max_payloads_per_param = 10
        self.stop_on_first_finding = True
    
    async def setup(self):
        """Initialize HTTP session"""
        if not self._http_session:
            self._http_session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                headers={'User-Agent': 'Mozilla/5.0'}
            )
    
    async def cleanup(self):
        """Clean up resources"""
        if self._http_session:
            await self._http_session.close()
            self._http_session = None
    
    async def scan_endpoint(self, endpoint: Endpoint) -> List[XSSFinding]:
        """Test an endpoint for XSS vulnerabilities"""
        findings = []
        
        # Skip endpoints without parameters
        if not endpoint.parameters:
            return findings
            
        self.logger.debug(f"Testing endpoint {endpoint.id}: {endpoint.full_url}")
        
        # Initialize HTTP session if needed
        if not self._http_session:
            await self.setup()
        
        # Test each parameter
        for param_name, param_value in endpoint.parameters.items():
            self.logger.debug(f"Testing parameter {param_name} in {endpoint.full_url}")
            
            # Test each payload
            for i, payload in enumerate(self.payloads):
                if i >= self.max_payloads_per_param:
                    break
                
                try:
                    # Send the test request
                    test_params = endpoint.parameters.copy()
                    test_params[param_name] = payload
                    
                    response_text = await self._send_request(
                        endpoint.full_url, 
                        endpoint.method, 
                        test_params
                    )
                    
                    # Check if the payload is in the response and not escaped
                    if payload in response_text:
                        # Additional check to avoid false positives
                        if self._is_valid_xss(response_text, payload):
                            finding = XSSFinding(
                                endpoint_url=endpoint.full_url,
                                endpoint_id=endpoint.id,
                                parameter=param_name,
                                payload=payload,
                                proof=self._extract_proof(response_text, payload),
                                severity=self._determine_severity(endpoint)
                            )
                            findings.append(finding)
                        
                        if self.stop_on_first_finding:
                            break
                
                except Exception as e:
                    self.logger.error(f"Error testing {endpoint.full_url}: {str(e)}")
                    continue
        
        return findings
    
    async def scan_target(self, target: str) -> List[XSSFinding]:
        """Scan all endpoints for a target domain"""
        findings = []
        
        # Get endpoints for the target
        endpoints = self.session.query(Endpoint).join(Subdomain).filter(
            (Subdomain.domain == target) | (Subdomain.domain.like(f'%.{target}')),
            Endpoint.parameters != None  # Only endpoints with parameters
        ).all()
        
        if not endpoints:
            self.logger.info(f"No endpoints with parameters found for {target}")
            return findings
        
        self.logger.info(f"Testing {len(endpoints)} endpoints for XSS vulnerabilities")
        
        # Scan each endpoint
        for endpoint in endpoints:
            endpoint_findings = await self.scan_endpoint(endpoint)
            findings.extend(endpoint_findings)
            
            if endpoint_findings:
                self.logger.info(f"Found {len(endpoint_findings)} XSS vulnerabilities in {endpoint.full_url}")
        
        return findings
    
    async def _send_request(self, url: str, method: str, params: Dict) -> str:
        """Send HTTP request and return response text with improved error handling"""
        # Sanitize parameters
        sanitized_params = self._sanitize_params(params)
        
        # Check if params contain special characters that might cause URL encoding issues
        has_special_chars = any(isinstance(v, str) and any(c in v for c in '<>"\'&;') for v in sanitized_params.values())
        
        # Force POST for payloads with special characters or long parameters
        if has_special_chars and method.upper() == "GET":
            method = "POST"
            self.logger.debug(f"Switching to POST due to special characters in parameters for: {url}")
        
        try:
            # First attempt with original method
            if method.upper() == "GET":
                async with self._http_session.get(url, params=sanitized_params) as response:
                    return await response.text()
            else:
                async with self._http_session.post(url, data=sanitized_params) as response:
                    return await response.text()
        except aiohttp.ClientResponseError as e:
            if ("header value is too long" in str(e).lower() or "too many bytes" in str(e).lower()) and method.upper() == "GET":
                # Fallback to POST if header is too long
                self.logger.debug(f"Header too long for GET request, falling back to POST: {url}")
                try:
                    async with self._http_session.post(url, data=sanitized_params) as response:
                        return await response.text()
                except Exception as post_e:
                    self.logger.error(f"POST fallback also failed: {str(post_e)}")
                    return f"Error: {str(post_e)}"
            else:
                self.logger.error(f"Request error: {e.status}, message='{str(e)}', url={url}")
                return f"Error: {str(e)}"  # Return error message instead of raising
        except Exception as e:
            self.logger.error(f"Request error: {str(e)}, url={url}")
            return f"Error: {str(e)}"  # Return error message instead of raising
    
    def _extract_proof(self, response_text: str, payload: str) -> str:
        """Extract proof snippet from response"""
        start_index = response_text.find(payload)
        if start_index == -1:
            return "Payload found but exact location unknown"
        
        # Get some context around the payload
        start = max(0, start_index - 40)
        end = min(len(response_text), start_index + len(payload) + 40)
        
        return response_text[start:end]
    
    def _sanitize_params(self, params: Dict) -> Dict:
        """Convert all parameter values to strings and handle special cases"""
        sanitized = {}
        for key, value in params.items():
            if value is None:
                sanitized[key] = ""
                continue
                
            if isinstance(value, (dict, list)):
                # Skip complex parameters that might cause issues
                self.logger.debug(f"Skipping complex parameter {key} due to potential type errors")
                continue
                
            try:
                sanitized[key] = str(value)
            except Exception as e:
                self.logger.error(f"Error sanitizing parameter {key}: {str(e)}")
                sanitized[key] = ""  # Use empty string as fallback
                
        return sanitized
    
    def _is_valid_xss(self, response_text: str, payload: str) -> bool:
        """Perform additional validation to reduce false positives"""
        # Simple check: if payload contains HTML tags, they should be unescaped in the response
        if '<' in payload and '>' in payload:
            # Check if the payload appears with HTML entities escaped
            escaped_payload = payload.replace('<', '&lt;').replace('>', '&gt;')
            if escaped_payload in response_text and payload not in response_text:
                return False
        
        return True
        
    def _determine_severity(self, endpoint: Endpoint) -> str:
        """Determine severity based on endpoint characteristics"""
        if endpoint.is_authenticated:
            return "high"
        return "medium"
