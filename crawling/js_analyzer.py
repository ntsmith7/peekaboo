import json
import re
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime
from urllib.parse import urljoin, urlparse

from core.models import JavaScript, Endpoint, EndpointSource
from infrastrucutre.database import DatabaseSession

@dataclass
class JavaScriptAnalysisResult:
    """Holds the results of JavaScript analysis without creating database models"""
    endpoints: Set[str]              # Raw endpoints found
    urls: Set[str]                   # Full URLs discovered
    variables: Dict                  # Interesting variables found
    config: Dict                     # Configuration objects
    source_url: str                  # URL of the analyzed file

class JavaScriptAnalyzer:
    """
    Analyzes JavaScript content to extract endpoints, variables, and other useful information.
    Separates analysis from model creation for better reusability and testing.
    """
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Initialize regex patterns for reuse
        self.endpoint_patterns = [
            # API endpoints with versioning
            r'["\']\/(?:api|v[0-9]+)\/[^"\']+["\']',
            
            # Resource endpoints with file extensions
            r'["\']\/[a-zA-Z0-9_\-\/]+\.(?:json|xml|html|php|aspx)["\']',
            
            # GraphQL endpoints
            r'["\']\/(?:graphql|gql|query)[^"\']*["\']',
            
            # Authentication related endpoints
            r'["\']\/(?:auth|login|logout|oauth|sso)[^"\']*["\']',
            
            # General paths that look like endpoints
            r'["\']\/[a-zA-Z0-9_\-\/]+(?:\/[a-zA-Z0-9_\-]+)*["\']'
        ]
        
        # Patterns for interesting variables
        self.variable_patterns = {
            'api_keys': [
                r'(?:api[_-]?key|client[_-]?id)["\']?\s*[:=]\s*["\']([^"\']+)',
                r'authorization["\']?\s*[:=]\s*["\']([^"\']+)'
            ],
            'endpoints': [
                r'(?:endpoint|url|uri|api_url)["\']?\s*[:=]\s*["\']([^"\']+)',
                r'(?:base|root)_url["\']?\s*[:=]\s*["\']([^"\']+)'
            ],
            'configs': [
                r'(?:config|configuration|settings)["\']?\s*[:=]\s*({[^;]+})',
                r'(?:options|params)["\']?\s*[:=]\s*({[^;]+})'
            ],
            'secrets': [
                r'(?:secret|token|password|key)["\']?\s*[:=]\s*["\']([^"\']+)',
                r'(?:auth|oauth)_token["\']?\s*[:=]\s*["\']([^"\']+)'
            ],
            'identifiers': [
                r'(?:account|user|tenant)_id["\']?\s*[:=]\s*["\']([^"\']+)',
                r'(?:project|org)_id["\']?\s*[:=]\s*["\']([^"\']+)'
            ]
        }

    def analyze(self, content: str, source_url: str) -> JavaScriptAnalysisResult:
        """
        Analyzes JavaScript content and returns structured data without creating models.
        
        Args:
            content: The JavaScript content to analyze
            source_url: Source URL of the JavaScript file
            
        Returns:
            JavaScriptAnalysisResult containing all extracted information
        """
        try:
            # Extract all useful information
            endpoints = self._extract_endpoints(content)
            urls = self._extract_urls(content)
            variables = self._extract_variables(content)
            config = self._extract_config(content)

            # Return raw analysis results
            return JavaScriptAnalysisResult(
                endpoints=endpoints,
                urls=urls,
                variables=variables,
                config=config,
                source_url=source_url
            )

        except Exception as e:
            self.logger.error(f"Error analyzing JavaScript from {source_url}: {str(e)}")
            raise

    def create_models(self, analysis_result: JavaScriptAnalysisResult, subdomain_id: int) -> Tuple[JavaScript, List[Endpoint]]:
        """
        Creates database models from analysis results.
        
        Args:
            analysis_result: The results from analyze()
            subdomain_id: Associated subdomain ID
            
        Returns:
            Tuple of (JavaScript model, List of Endpoint models)
        """
        # Create JavaScript record with enriched metadata
        js_file = JavaScript(
            subdomain_id=subdomain_id,
            url=analysis_result.source_url,
            endpoints_referenced=list(analysis_result.endpoints),
            variables={
                'extracted_urls': list(analysis_result.urls),
                'config': analysis_result.config,
                'interesting_vars': analysis_result.variables,
                'metadata': {
                    'total_endpoints': len(analysis_result.endpoints),
                    'total_urls': len(analysis_result.urls),
                    'has_sensitive_data': bool(analysis_result.variables.get('secrets')),
                    'api_related': any('/api/' in url for url in analysis_result.urls)
                }
            },
            discovery_time=datetime.utcnow()
        )

        # Create endpoints for each discovered path
        endpoint_models = []
        base_url = urlparse(analysis_result.source_url)
        
        # Combine both endpoints and full URLs for processing
        all_urls = set(analysis_result.endpoints)
        all_urls.update(url for url in analysis_result.urls 
                       if urlparse(url).netloc == base_url.netloc)
        
        for url in all_urls:
            try:
                full_url = urljoin(analysis_result.source_url, url)
                parsed = urlparse(full_url)
                
                # Skip invalid or external URLs
                if not parsed.netloc or not parsed.path:
                    continue
                    
                path_segments = [seg for seg in parsed.path.strip('/').split('/') if seg]
                
                endpoint_model = Endpoint(
                    subdomain_id=subdomain_id,
                    full_url=full_url,
                    domain=parsed.netloc,
                    path_segments=path_segments,
                    endpoint_type=self._determine_endpoint_type(parsed.path),
                    source_page=analysis_result.source_url,
                    discovery_tag='script',
                    discovery_attribute='src',
                    method=self._determine_http_method(url, analysis_result.variables),
                    discovery_time=datetime.utcnow(),
                    # Add parameter info if available in the URL
                    parameters=self._extract_url_parameters(parsed) if parsed.query else {},
                    additional_info={
                        'discovery_context': 'javascript_analysis',
                        'related_variables': self._find_related_variables(url, analysis_result.variables)
                    }
                )
                endpoint_models.append(endpoint_model)
                
            except Exception as e:
                self.logger.error(f"Error creating endpoint model for {url}: {str(e)}")
                continue

        return js_file, endpoint_models

    def _extract_endpoints(self, content: str) -> Set[str]:
        """Extract API endpoints and paths from JavaScript content"""
        endpoints = set()
        
        for pattern in self.endpoint_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                # Clean up the matched endpoint
                endpoint = match.group(0).strip('\'"')
                if self._is_valid_endpoint(endpoint):
                    endpoints.add(endpoint)
                    
        return endpoints

    def _extract_urls(self, content: str) -> Set[str]:
        """Extract full URLs from JavaScript content"""
        urls = set()
        
        # URL pattern that handles various formats
        url_patterns = [
            # Standard URLs
            r'https?://[^\s\'"]+[\w]',
            # URLs in template literals
            r'`https?://[^`]+`',
            # URLs with parameters
            r'https?://[^\s\'"]+\?[^\s\'"]+',
        ]
        
        for pattern in url_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                url = match.group(0)
                # Clean up the URL
                url = url.strip('`\'"')
                if url.endswith(("'", '"', ")", "]", ";")):
                    url = url[:-1]
                urls.add(url)
            
        return urls

    def _extract_variables(self, content: str) -> Dict:
        """Extract interesting variables and their values"""
        variables = {}
        
        for category, patterns in self.variable_patterns.items():
            values = set()
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                values.update(match.group(1) for match in matches)
            if values:
                variables[category] = list(values)
                
        return variables

    def _extract_config(self, content: str) -> Dict:
        """Extract configuration objects"""
        config = {}
        
        # Config patterns with context
        config_patterns = [
            (r'\$Config\s*=\s*({[^;]+})', 'global'),
            (r'config\s*=\s*({[^;]+})', 'local'),
            (r'configuration\s*=\s*({[^;]+})', 'local'),
            (r'settings\s*=\s*({[^;]+})', 'settings')
        ]
        
        for pattern, context in config_patterns:
            matches = re.search(pattern, content)
            if matches:
                try:
                    config_str = matches.group(1)
                    # Clean up the config string
                    config_str = re.sub(r'([{,]\s*)([a-zA-Z0-9_]+)\s*:', r'\1"\2":', config_str)
                    config_str = re.sub(r',\s*}', '}', config_str)  # Remove trailing commas
                    parsed_config = json.loads(config_str)
                    config[context] = parsed_config
                except json.JSONDecodeError:
                    self.logger.debug(f"Failed to parse config with context {context}")
                    continue
                    
        return config

    def _determine_endpoint_type(self, path: str) -> str:
        """Intelligently determine the endpoint type based on the path"""
        path_lower = path.lower()
        
        # Check for API endpoints
        if '/api/' in path_lower or '/v1/' in path_lower or '/v2/' in path_lower:
            return 'api'
        
        # Check for authentication endpoints
        elif any(auth in path_lower for auth in ['/auth/', '/login/', '/oauth/', '/sso/']):
            return 'auth'
        
        # Check for file operations
        elif any(file in path_lower for file in ['/upload/', '/download/', '/file/']):
            return 'file'
        
        # Check for resource endpoints
        elif any(ext in path_lower for ext in ['.json', '.xml', '.html', '.pdf']):
            return 'resource'
        
        # Check for GraphQL
        elif '/graphql' in path_lower or '/gql' in path_lower:
            return 'graphql'
            
        return 'unknown'

    def _determine_http_method(self, endpoint: str, variables: Dict) -> str:
        """Try to determine the likely HTTP method for an endpoint"""
        endpoint_lower = endpoint.lower()
        
        # Check endpoint path for hints
        if any(word in endpoint_lower for word in ['create', 'add', 'upload', 'post']):
            return 'POST'
        elif any(word in endpoint_lower for word in ['update', 'modify', 'edit', 'put']):
            return 'PUT'
        elif any(word in endpoint_lower for word in ['delete', 'remove']):
            return 'DELETE'
        elif any(word in endpoint_lower for word in ['get', 'fetch', 'download']):
            return 'GET'
            
        # Check if endpoint is referenced in variables with method hints
        for var_list in variables.values():
            for var in var_list:
                if isinstance(var, str) and endpoint in var:
                    if 'post' in var.lower():
                        return 'POST'
                    elif 'put' in var.lower():
                        return 'PUT'
                    elif 'delete' in var.lower():
                        return 'DELETE'
        
        return 'GET'

    def _is_valid_endpoint(self, endpoint: str) -> bool:
        """Validate if an extracted endpoint is likely to be real"""
        if not endpoint.startswith('/'):
            return False
            
        # Ignore common false positives
        ignored_patterns = [
            r'/\d+\.\d+\.\d+',  # Version numbers
            r'/\d{4}/\d{2}',    # Date patterns
            r'/[a-f0-9]{32}',   # MD5 hashes
            r'/[a-f0-9]{40}',   # SHA1 hashes
            r'/static/\d+',     # Static resource versions
            r'/\d+px',          # Image dimensions
        ]
        
        for pattern in ignored_patterns:
            if re.search(pattern, endpoint):
                return False
                
        return True

    def _extract_url_parameters(self, parsed_url) -> Dict:
        """Extract and structure URL parameters"""
        if not parsed_url.query:
            return {}
            
        params = {}
        for param in parsed_url.query.split('&'):
            if '=' in param:
                key, value = param.split('=', 1)
                params[key] = value
                
        return {'query_parameters': params}

    def _find_related_variables(self, url: str, variables: Dict) -> Dict:
        """Find variables that might be related to this URL"""
        related = {}
        
        for category, values in variables.items():
            related_vars = []
            for value in values:
                if isinstance(value, str) and (url in value or value in url):
                    related_vars.append(value)
            if related_vars:
                related[category] = related_vars
                
        return related