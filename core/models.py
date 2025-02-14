from datetime import datetime
import enum
from dataclasses import dataclass
from typing import Dict, Optional
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Integer,
    JSON,
    String,
    ForeignKey,
)

from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class SubdomainSource(enum.Enum):
    CERTIFICATE = "certificate"
    DNS = "dns_enumeration"
    WAYBACK = "wayback"
    BRUTEFORCE = "bruteforce"
    PASSIVE = "passive"


class Subdomain(Base):
    __tablename__ = 'subdomains'
    id = Column(Integer, primary_key=True)
    domain = Column(String, nullable=False)
    source = Column(Enum(SubdomainSource))
    discovery_time = Column(DateTime, default=datetime.utcnow)
    is_alive = Column(Boolean, default=False)
    ip_addresses = Column(JSON)
    http_status = Column(Integer)
    additional_info = Column(JSON)
    last_checked = Column(DateTime, nullable=True)
    is_takeover_candidate = Column(Boolean, default=False)


class EndpointSource(enum.Enum):
    CRAWL = "crawler"
    JS_PARSE = "javascript_parser"
    FORM = "form_submission"
    REDIRECT = "redirect_chain"

class Endpoint(Base):
    __tablename__ = 'endpoints'
    id = Column(Integer, primary_key=True)
    subdomain_id = Column(Integer, ForeignKey('subdomains.id'))
    
    # URL Components
    full_url = Column(String, nullable=False)  # Complete URL as found
    domain = Column(String, nullable=False)    # e.g. 'www.coolblue.nl'
    path_segments = Column(JSON)               # e.g. ['product', '947017', 'samsung-music-frame']
    endpoint_type = Column(String)             # e.g. 'product'
    resource_id = Column(String)               # e.g. '947017'
    
    # Discovery Context
    source_page = Column(String)               # Where this URL was found
    discovery_tag = Column(String)             # HTML element (e.g. 'a')
    discovery_attribute = Column(String)       # Element attribute (e.g. 'href')
    discovery_time = Column(DateTime, default=datetime.utcnow)
    
    # Request/Response Data
    method = Column(String)
    status_code = Column(Integer)
    content_type = Column(String)
    response_size = Column(Integer)
    parameters = Column(JSON)                  # Query/form parameters
    is_authenticated = Column(Boolean)         # Found while authenticated?
    additional_info = Column(JSON)             # Extra metadata

class JavaScript(Base):
    __tablename__ = 'javascript_files'
    id = Column(Integer, primary_key=True)
    subdomain_id = Column(Integer, ForeignKey('subdomains.id'))
    url = Column(String, nullable=False)
    file_hash = Column(String)  # To track changes over time
    endpoints_referenced = Column(JSON)  # API endpoints found in the code
    variables = Column(JSON)  # Interesting variables/config
    discovery_time = Column(DateTime, default=datetime.utcnow)
    last_modified = Column(DateTime)


@dataclass
class KatanaResult:
    """Data class for storing Katana crawler results"""
    timestamp: str                # ISO format timestamp
    request: Dict                 # Contains method, endpoint, tag, attribute, source
    url: str                      # Full URL (added for compatibility)
    method: str                   # HTTP method
    status_code: Optional[int]    # Response status
    content_type: Optional[str]   # Response content type
    response_size: Optional[int]  # Response size in bytes
    parameters: Dict              # URL/form parameters
    headers: Dict                 # Response headers
    response_body: Optional[str]  # Response content
