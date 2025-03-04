# main.py
import asyncio
import logging
import time
import sys
import signal
import argparse
from datetime import datetime
from pathlib import Path

# Import rich for better terminal output
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.logging import RichHandler
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

# Setup rich console
console = Console()

# Import and setup logging with Rich
from infrastructure.logging_config import setup_logging
logger = setup_logging(logging.INFO, handler=RichHandler(console=console))

def flush_logging_handlers():
    """Ensure all logging handlers are flushed"""
    for handler in logger.handlers:
        try:
            handler.flush()
        except Exception as e:
            console.print(f"[bold red]Error flushing log handler: {str(e)}[/bold red]")

def check_dependencies():
    """Check if all required dependencies are installed"""
    import shutil
    
    console.print(Panel("Checking dependencies", title="Setup"))
    
    # Check subfinder
    subfinder_path = shutil.which('subfinder')
    if not subfinder_path:
        console.print("[bold red]Required dependency 'subfinder' not found in PATH[/bold red]")
        return False
    console.print(f"[green]Found subfinder at:[/green] {subfinder_path}")
    
    # Check katana
    katana_path = shutil.which('katana')
    if not katana_path:
        console.print("[bold red]Required dependency 'katana' not found in PATH[/bold red]")
        return False
    console.print(f"[green]Found katana at:[/green] {katana_path}")
    
    return True

def create_parser():
    """Create command-line argument parser with subcommands"""
    parser = argparse.ArgumentParser(description='Peekaboo Security Scanner')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    # Create subcommands
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Discover command
    discover_parser = subparsers.add_parser('discover', help='Discover subdomains')
    discover_parser.add_argument('target', help='Target domain to scan (e.g., example.com)')
    discover_parser.add_argument('--rate-limit', type=int, default=5, help='Rate limit for discovery tools')
    discover_parser.add_argument('--timeout', type=int, default=300, help='Timeout in seconds')
    discover_parser.add_argument('--bruteforce', action='store_true', help='Include bruteforce discovery')
    
    # Crawl command
    crawl_parser = subparsers.add_parser('crawl', help='Crawl discovered subdomains')
    crawl_parser.add_argument('--target', help='Target domain to filter subdomains')
    crawl_parser.add_argument('--id', type=int, nargs='+', help='Specific subdomain IDs to crawl')
    crawl_parser.add_argument('--timeout', type=int, default=180, help='Timeout in seconds per crawl')
    crawl_parser.add_argument('--max-concurrent', type=int, default=5, help='Maximum concurrent crawls')
    crawl_parser.add_argument('--live-only', action='store_true', help='Only crawl live subdomains')
    crawl_parser.add_argument('--exact-match', action='store_true', help='Require exact domain match instead of substring')
    
    return parser

def clean_target_url(target: str) -> str:
    """
    Standardize target URL format by removing common prefixes and trailing slashes.
    
    Args:
        target: The target URL or domain to clean
        
    Returns:
        Cleaned target string
    """
    target = target.lower()
    for prefix in ['https://', 'http://', 'www.']:
        if target.startswith(prefix):
            target = target[len(prefix):]
    return target.strip('/')


async def handle_discovery(args):
    """Handle subdomain discovery with proper resource management"""
    from infrastructure.database import DatabaseSession, init_database
    from discovery.network import NetworkOperations
    from discovery.scanner import SubdomainScanner
    from discovery.repository import SubdomainRepository
    from discovery.service import DiscoveryService
    from core.models import Subdomain
    
    # Clean target URL
    target = clean_target_url(args.target)
    
    # Setup logging and progress display
    console.print(Panel(
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Rate limit:[/bold] {args.rate_limit}\n"
        f"[bold]Timeout:[/bold] {args.timeout} seconds\n"
        f"[bold]Bruteforce:[/bold] {'Yes' if args.bruteforce else 'No'}",
        title="Starting Subdomain Discovery",
        border_style="blue"
    ))
    start_time = time.time()
    
    # Initialize database
    console.print("Initializing database...")
    init_database()
    
    # Create database session
    db_session = DatabaseSession()
    
    try:
        # Create service components with sequential error handling
        try:
            console.print("Setting up network operations...")
            network_ops = NetworkOperations(timeout=args.timeout)
            
            console.print("Setting up scanner...")
            scanner = SubdomainScanner(rate_limit=args.rate_limit)
            
            console.print("Setting up repository...")
            repository = SubdomainRepository(db_session.session, Subdomain)
            
            # Initialize network resources
            console.print("Initializing network resources...")
            await network_ops.setup()
            
            # Create discovery service
            console.print("Creating discovery service...")
            discovery_service = DiscoveryService(network_ops, scanner, repository)
            
        except Exception as e:
            console.print(f"[bold red]Error during setup: {str(e)}[/bold red]")
            logger.error(f"Setup error: {str(e)}", exc_info=True)
            return 1
        
        # Run discovery with comprehensive error handling
        try:
            console.print(Panel("[bold]Discovering subdomains...[/bold]", border_style="yellow"))
            
            # Using with_progress context manager for live updates
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}[/bold blue]"),
                BarColumn(),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                task = progress.add_task("Scanning subdomains...", total=None)
                
                # Run discovery
                results = await discovery_service.discover(target, include_bruteforce=args.bruteforce)
                progress.update(task, description=f"Found {len(results)} subdomains")
            
            # Calculate statistics
            duration = time.time() - start_time
            total_count = len(results)
            live_count = sum(1 for r in results if r.get('is_alive', False))
            
            # Log summary
            console.print()
            console.print(Panel(
                f"Duration: [bold]{duration:.2f}[/bold] seconds\n"
                f"Total subdomains: [bold]{total_count}[/bold]\n"
                f"Live subdomains: [bold green]{live_count}[/bold green]\n"
                f"Dead subdomains: [bold red]{total_count - live_count}[/bold red]",
                title="Discovery Results",
                border_style="green"
            ))
            
            # Display results table
            if results:
                console.print()
                
                table = Table(title="Subdomain Details")
                table.add_column("Domain", style="cyan")
                table.add_column("Status", style="bold")
                table.add_column("HTTP", justify="right")
                table.add_column("IPs", justify="right")
                table.add_column("Takeover?")
                
                for result in results:
                    status = "[green]LIVE[/green]" if result.get('is_alive', False) else "[red]DEAD[/red]"
                    http_status = str(result.get('http_status', 'N/A'))
                    takeover = "[red]YES[/red]" if result.get('is_takeover_candidate', False) else "NO"
                    ip_count = len(result.get('ip_addresses', []))
                    
                    table.add_row(
                        result.get('domain', 'Unknown'),
                        status,
                        http_status,
                        str(ip_count),
                        takeover
                    )
                
                console.print(table)
            
            return 0
        except asyncio.CancelledError:
            console.print("[yellow]Discovery operation cancelled[/yellow]")
            # Don't re-raise, allow cleanup in finally blocks
            return 1
        except Exception as e:
            console.print(f"[bold red]Discovery failed: {str(e)}[/bold red]")
            logger.error(f"Discovery failed: {str(e)}", exc_info=True)
            return 1
        finally:
            # Always clean up network resources
            console.print("Cleaning up network resources...")
            await network_ops.cleanup()
    finally:
        # Always close the database session
        console.print("Closing database session...")
        db_session.close()

async def handle_crawl(args):
    """Handle the crawl command using existing code"""
    from infrastructure.database import DatabaseSession
    from crawling.service import CrawlingService
    from core.models import Subdomain
    
    console.print(Panel("Starting Crawling Process", 
                        title="Crawl", 
                        title_align="left", 
                        border_style="blue"))
    start_time = time.time()
    
    # Create database session
    db_session = DatabaseSession()
    
    try:
        # Determine subdomain IDs to crawl
        subdomain_ids = args.id
        if not subdomain_ids and args.target:
            console.print(f"Looking up subdomains for target: [bold]{args.target}[/bold]")
            
            # Query subdomains by target domain
            subdomains = db_session.session.query(Subdomain)\
                .filter(Subdomain.domain.like(f"%{args.target}%"))\
                .all()
            
            if not subdomains:
                console.print("[bold red]No subdomains found for target[/bold red]")
                return 1
                
            subdomain_ids = [sub.id for sub in subdomains]
            
            # Display found subdomains
            table = Table(title=f"Found {len(subdomain_ids)} subdomains to crawl")
            table.add_column("ID", justify="right")
            table.add_column("Domain")
            table.add_column("Status")
            
            for sub in subdomains:
                status = "[green]LIVE[/green]" if sub.is_alive else "[red]DEAD[/red]"
                table.add_row(str(sub.id), sub.domain, status)
            
            console.print(table)
        
        if not subdomain_ids:
            console.print("[bold red]No subdomains specified for crawling. Use --id or --target[/bold red]")
            return 1
        
        console.print(f"Crawling [bold]{len(subdomain_ids)}[/bold] subdomains")
        console.print(f"Max concurrent crawls: [bold]{args.max_concurrent}[/bold]")
        console.print(f"Timeout per crawl: [bold]{args.timeout}[/bold] seconds")
        
        # Create crawling service
        crawling_service = CrawlingService(db_session)
        crawling_service.max_concurrent_crawls = args.max_concurrent
        
        try:
            # Run crawling
            await crawling_service.crawl_specific_targets(subdomain_ids)
            
            # Report results
            duration = time.time() - start_time
            
            console.print()
            console.print(Panel(
                f"Duration: [bold]{duration:.2f}[/bold] seconds\n"
                f"Subdomains crawled: [bold]{len(subdomain_ids)}[/bold]",
                title="Crawling Complete",
                border_style="green"
            ))
            
            return 0
        finally:
            # Clean up resources
            await crawling_service.close()
    except Exception as e:
        logger.error(f"Crawling failed: {str(e)}", exc_info=True)
        return 1
    finally:
        # Close database session
        db_session.close()


# Helper functions to count results
def count_endpoints(db_session, target):
    """Count endpoints for a target domain"""
    try:
        from core.models import Endpoint, Subdomain
        return db_session.session.query(Endpoint).join(Subdomain).filter(
            (Subdomain.domain == target) | (Subdomain.domain.like(f'%.{target}'))
        ).count()
    except Exception as e:
        logger.error(f"Error counting endpoints: {str(e)}")
        return 0

def count_js_files(db_session, target):
    """Count JavaScript files for a target domain"""
    try:
        from core.models import JavaScript, Subdomain
        return db_session.session.query(JavaScript).join(Subdomain).filter(
            (Subdomain.domain == target) | (Subdomain.domain.like(f'%.{target}'))
        ).count()
    except Exception as e:
        logger.error(f"Error counting JavaScript files: {str(e)}")
        return 0

async def main():
    """Main entry point with improved command handling"""
    # Create argument parser with subcommands
    parser = create_parser()
    args = parser.parse_args()
    
    # Set log level
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    # Print application banner
    console.print(Panel.fit(
        "[bold blue]Peekaboo Security Scanner[/bold blue]\n"
        f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        border_style="bold blue"
    ))
    
    # Ensure logs directory exists
    Path('logs').mkdir(exist_ok=True)
    
    # Check dependencies
    if not check_dependencies():
        return 1
    
    # Run the appropriate command
    if hasattr(args, 'command') and args.command:
        if args.command == 'discover':
            return await handle_discovery(args)
        elif args.command == 'crawl':
            return await handle_crawl(args)
        else:
            console.print(f"[bold red]Unknown command: {args.command}[/bold red]")
            parser.print_help()
            return 1
    else:
        # If no command specified, show help
        parser.print_help()
        return 1

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
            # Set up signal handlers
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, lambda s=sig: handle_signal(loop, main_task, s))
            
            exit_code = loop.run_until_complete(main_task)
        except KeyboardInterrupt:
            console.print("[yellow]Received shutdown signal, stopping gracefully...[/yellow]")
            exit_code = handle_shutdown(loop, main_task)
        finally:
            # Remove signal handlers
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.remove_signal_handler(sig)
            
            # Ensure all tasks are cancelled
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()
            
            # Run loop until all tasks complete
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            
            # Close the loop
            loop.close()
            
        sys.exit(exit_code)
            
    except Exception as e:
        console.print(f"[bold red]Fatal error:[/bold red] {str(e)}")
        console.print_exception()
        sys.exit(1)

def handle_signal(loop: asyncio.AbstractEventLoop, main_task: asyncio.Task, sig: int):
    """Handle received signals"""
    console.print(f"[yellow]Received signal {sig}, initiating graceful shutdown...[/yellow]")
    handle_shutdown(loop, main_task)

def handle_shutdown(loop: asyncio.AbstractEventLoop, main_task: asyncio.Task) -> int:
    """Handle graceful shutdown of the application"""
    try:
        # Cancel the main task
        main_task.cancel()

        console.print("[yellow]Shutdown initiated. Waiting for tasks to complete...[/yellow]")
        
        # Wait for cancellation to complete
        # try:
        #     loop.run_until_complete(main_task)
        # except asyncio.CancelledError:
        #     pass
        
        # Ensure logs are flushed
        flush_logging_handlers()
        return 0
    except Exception as e:
        console.print(f"[bold red]Error during shutdown:[/bold red] {str(e)}")
        flush_logging_handlers()
        return 1

if __name__ == "__main__":
    run()