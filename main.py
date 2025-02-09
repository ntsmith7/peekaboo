import asyncio
from utils.logging_config import setup_logging, get_logger
from models.scanner import SubdomainScanner
from utils.database import db_manager


# Initialize logging
logger = get_logger(__name__)


async def main():
    """Main entry point for the scanner"""
    # Setup application-wide logging and database
    setup_logging()
    
    # Ensure database is initialized
    db_manager._setup_engine()
    
    try:
        target = "https://www.deere.com"
        logger.info(f"Starting subdomain scanner for target: {target}")
        await SubdomainScanner.scan_target(target)
        logger.info("Scan completed. Results saved to scan_results.json")
    except Exception as e:
        logger.error(f"Fatal error in main: {str(e)}", exc_info=True)
        raise


if __name__ == "__main__":
    asyncio.run(main())
