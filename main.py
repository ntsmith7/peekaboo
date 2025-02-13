# main.py
import asyncio
import logging
import time
import sys
import argparse
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

# Import and setup logging first
from infrastrucutre.logging_config import setup_logging
logger = setup_logging(logging.INFO)

def check_dependencies():
    """Check if all required dependencies are installed"""
    # Check subfinder
    subfinder_path = shutil.which('subfinder')
    if not subfinder_path:
        logger.error("Required dependency 'subfinder' not found in PATH")
        return False
    logger.info(f"Found subfinder at: {subfinder_path}")
    
    # Check katana
    katana_path = shutil.which('katana')
    if not katana_path:
        logger.error("Required dependency 'katana' not found in PATH")
        return False
    logger.info(f"Found katana at: {katana_path}")
    
    return True

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Peekaboo Security Scanner')
    parser.add_argument('target', help='Target domain to scan (e.g., example.com)')
    parser.add_argument('--timeout', type=int, default=3600,
                      help='Maximum scan duration in seconds (default: 3600)')
    parser.add_argument('--debug', action='store_true',
                      help='Enable debug logging')
    return parser.parse_args()

try:
    # Import dependencies
    import shutil
    if not check_dependencies():
        sys.exit(1)
    
    # Initialize database
    from infrastrucutre.database import init_database, DatabaseSession
    logger.info("Initializing database...")
    init_database()
    logger.info("Database initialization complete")
    
    # Now import the rest of the modules
    logger.info("Loading system modules...")
    from discovery.scanner import SubdomainDiscovery
    from core.coordinator import ScanCoordinator
    from crawling.service import CrawlingService
except ImportError as e:
    logger.error(f"Failed to import required modules: {str(e)}")
    sys.exit(1)

async def main():
    """
    Main entry point for the security scanner
    """
    args = parse_args()
    
    # Set log level
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    start_time = time.time()
    logger.info(f"""
==================================
Starting Peekaboo Security Scanner
==================================
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Target: {args.target}
Timeout: {args.timeout} seconds
    """.strip())

    # Ensure logs directory exists
    Path('logs').mkdir(exist_ok=True)
    
    try:
        # Create a shared database session
        db_session = DatabaseSession()
        
        try:
            # Initialize the coordinator with the database session
            logger.info(f"Initiating security assessment for {args.target}")
            coordinator = ScanCoordinator(args.target)
            
            try:
                result = await coordinator.start_scan(timeout=args.timeout)
                if result.get('status') == 'error':
                    logger.error(f"Scan failed: {result.get('error')}")
                    return 1
                
                duration = time.time() - start_time
                logger.info(f"""
==================================
Scan Complete
==================================
Duration: {duration:.1f} seconds
Status: {result.get('status')}
Total Subdomains: {result.get('total_subdomains')}
Live Subdomains: {result.get('statistics', {}).get('live_subdomains')}
Endpoints: {result.get('statistics', {}).get('endpoints_discovered')}
JavaScript Files: {result.get('statistics', {}).get('js_files_found')}
                """.strip())
                return 0
                
            except asyncio.CancelledError:
                logger.info("Scan cancelled by user")
                return 0
            except Exception as e:
                logger.error(f"Scan failed: {str(e)}")
                return 1
        finally:
            # Clean up database session
            db_session.close()
                
    except Exception as e:
        logger.error(f"Fatal error in main: {str(e)}", exc_info=True)
        return 1
    finally:
        logger.info("Shutting down Peekaboo Security Scanner...")

def run():
    """Entry point with proper signal handling"""
    try:
        # Create event loop explicitly to handle signals
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Create main task
        main_task = loop.create_task(main())
        exit_code = 0
        
        try:
            exit_code = loop.run_until_complete(main_task)
        except KeyboardInterrupt:
            logger.info("Received shutdown signal, stopping gracefully...")
            # Cancel the main task and wait for it to complete
            main_task.cancel()
            try:
                exit_code = loop.run_until_complete(main_task)
            except asyncio.CancelledError:
                exit_code = 0
        finally:
            loop.close()
            
        sys.exit(exit_code)
            
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    run()
