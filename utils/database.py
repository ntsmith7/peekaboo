from contextlib import contextmanager
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from utils.logging_config import get_logger

from models.models import Base

logger = get_logger(__name__)

class DatabaseManager:
    def __init__(self, database_url=None):
        self.database_url = database_url or os.getenv('DATABASE_URL', 'sqlite:///subdomains.db')
        self.engine = None
        self.SessionFactory = None
        self._setup_engine()

    def _setup_engine(self):
        """Initialize database engine and session factory"""
        try:
            self.engine = create_engine(self.database_url)
            Base.metadata.create_all(self.engine)
            self.SessionFactory = sessionmaker(bind=self.engine)
            logger.info(f"Database engine initialized with URL: {self.database_url}")
        except Exception as e:
            logger.error(f"Failed to initialize database: {str(e)}")
            raise

    @contextmanager
    def session_scope(self) -> Session:
        """Provide a transactional scope around a series of operations."""
        session = self.SessionFactory()
        try:
            yield session
            session.commit()
        except Exception as e:
            logger.error(f"Session error: {str(e)}")
            session.rollback()
            raise
        finally:
            session.close()

    def save_subdomain(self, session: Session, subdomain_data: dict):
        """Save a subdomain to the database"""
        from models.models import Subdomain, SubdomainSource
        try:
            # Convert string source to enum
            source_str = subdomain_data.get('source', 'PASSIVE').upper()
            source = getattr(SubdomainSource, source_str)
            
            subdomain = Subdomain(
                domain=subdomain_data['domain'],
                source=source,
                is_alive=subdomain_data.get('is_alive', False),
                ip_addresses=subdomain_data.get('ip_addresses', []),
                http_status=subdomain_data.get('http_status'),
                is_takeover_candidate=subdomain_data.get('is_takeover_candidate', False),
                additional_info=subdomain_data.get('additional_info', {})
            )
            session.add(subdomain)
            logger.debug(f"Saved subdomain to database: {subdomain_data['domain']}")
            return subdomain
        except Exception as e:
            logger.error(f"Error saving subdomain {subdomain_data.get('domain')}: {str(e)}")
            raise

# Global database manager instance
db_manager = DatabaseManager()
