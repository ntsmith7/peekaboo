from datetime import datetime
import logging
from core.models import Subdomain

logger = logging.getLogger(__name__)

def save_subdomain(session, subdomain_data):
    """Save subdomain data to database"""
    subdomain = Subdomain(
        domain=subdomain_data['domain'],
        source=subdomain_data['source'],
        ip_addresses=subdomain_data['ip_addresses'],
        is_alive=subdomain_data['is_alive'],
        is_takeover_candidate=subdomain_data['is_takeover_candidate'],
        http_status=subdomain_data['http_status'],
        discovery_time=datetime.fromisoformat(subdomain_data['discovery_time']),
        last_checked=datetime.fromisoformat(subdomain_data['last_checked'])
    )
    session.add(subdomain)
