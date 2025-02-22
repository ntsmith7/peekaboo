from typing import Dict, Any
from infrastructure.logging_config import get_logger

class SubdomainRepository:
    """Handles data persistence for subdomain discovery results"""
    
    def __init__(self, db_session, subdomain_model):
        self.session = db_session
        self.model = subdomain_model
        self.logger = get_logger(__name__)

    async def save(self, result: Dict[str, Any]):
        """Save or update a subdomain record"""
        try:
            existing = self.session.query(self.model).filter(
                self.model.domain == result['domain']
            ).first()

            if existing:
                # Update existing record
                for key, value in result.items():
                    if hasattr(existing, key):
                        setattr(existing, key, value)
                existing.last_checked = None  # Reset to trigger crawl
            else:
                # Create new record
                subdomain = self.model(**result)
                subdomain.last_checked = None  # Reset to trigger crawl
                self.session.add(subdomain)

            self.session.commit()
            
        except Exception as e:
            self.logger.error(f"Database error saving {result['domain']}: {str(e)}")
            self.session.rollback()
            raise
