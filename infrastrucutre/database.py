from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from contextlib import contextmanager
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

# Create SQLite engine
engine = create_engine('sqlite:///subdomains.db', echo=False)

def init_database():
    """Initialize database and create tables"""
    from core.models import Base
    Base.metadata.create_all(engine)

# Create session factory
SessionFactory = sessionmaker(bind=engine)

class DatabaseSession:
    """
    Database session manager that handles SQLAlchemy session lifecycle.
    Can be used both as a context manager or directly.
    """
    def __init__(self):
        self._session = None

    @property
    def session(self) -> Session:
        if not self._session:
            self._session = SessionFactory()
        return self._session

    def close(self):
        """Closes the current session if it exists"""
        if self._session:
            try:
                self._session.close()
            except Exception as e:
                logger.error(f"Error closing database session: {str(e)}")
            finally:
                self._session = None

    def commit(self):
        """Commits the current transaction"""
        try:
            self.session.commit()
        except Exception as e:
            logger.error(f"Error committing transaction: {str(e)}")
            self.session.rollback()
            raise

    def rollback(self):
        """Rolls back the current transaction"""
        try:
            self.session.rollback()
        except Exception as e:
            logger.error(f"Error rolling back transaction: {str(e)}")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            # An error occurred, rollback
            self.rollback()
        self.close()

    def query(self, *args, **kwargs):
        """Convenience method to directly query the session"""
        return self.session.query(*args, **kwargs)

    def bulk_save_objects(self, objects, return_defaults=False, update_changed_only=True):
        """Convenience method to perform bulk save operations"""
        try:
            self.session.bulk_save_objects(objects, return_defaults=return_defaults, update_changed_only=update_changed_only)
        except Exception as e:
            logger.error(f"Error performing bulk save: {str(e)}")
            self.session.rollback()
            raise

    def add(self, obj):
        """Add object to the session"""
        self.session.add(obj)


class DatabaseManager:
    """
    Manages database operations with context management
    """
    @contextmanager
    def session_scope(self):
        """Provide a transactional scope around a series of operations."""
        session = SessionFactory()
        try:
            yield session
            session.commit()
        except Exception as e:
            logger.error(f"Error in database transaction: {str(e)}")
            session.rollback()
            raise
        finally:
            session.close()

    def save_subdomain(self, session, subdomain_data):
        """Save subdomain data to database"""
        from core.models import Subdomain
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
