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
    path = Column(String, nullable=False)
    method = Column(String)
    source = Column(Enum(EndpointSource))
    discovery_time = Column(DateTime, default=datetime.utcnow)
    content_type = Column(String)
    status_code = Column(Integer)
    response_size = Column(Integer)
    parameters = Column(JSON)  # Stores discovered URL/form parameters
    is_authenticated = Column(Boolean)  # Did we find this while authenticated?
    additional_info = Column(JSON)  # For framework-specific details

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
    url: str
    method: str
    status_code: Optional[int]
    content_type: Optional[str]
    response_size: Optional[int]
    parameters: Dict
    headers: Dict
    response_body: Optional[str]
    source: str
