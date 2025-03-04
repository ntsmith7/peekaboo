from datetime import datetime
import asyncio
import logging
from typing import List, Dict, Set, Any

# Import Rich components
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table

# Use a shared console
console = Console()

class DiscoveryService:
    """
    Service responsible for discovering subdomains for a target
    and persisting them to the database.
    """
    def __init__(self, network_ops, scanner, repository):
        """
        Initialize with required dependencies.
        """
        self.network = network_ops
        self.scanner = scanner
        self.repository = repository
        self.logger = logging.getLogger(__name__)
        
        # Track discovered subdomains
        self.discovered: Set[str] = set()
        self.results: List[Dict[str, Any]] = []

    async def discover(self, target: str, include_bruteforce: bool = False) -> List[Dict[str, Any]]:
        """
        Discover subdomains for the target domain.
        """
        start_time = datetime.utcnow()
        console.print(Panel(
            f"[bold]Target:[/bold] {target}\n"
            f"[bold]Bruteforce:[/bold] {'Yes' if include_bruteforce else 'No'}\n",
            title="Starting Subdomain Discovery",
            border_style="blue"
        ))
        
        # Reset state for new discovery
        self.discovered.clear()
        self.results.clear()
        
        try:
            # Check base domain first - with visual feedback
            console.print("[bold cyan]Checking base domain...[/bold cyan]")
            await self._process_subdomain(target, "BASE")
            
            # Run passive scanning with progress indicator
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]Running passive scan...[/bold blue]"),
                BarColumn(),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                scan_task = progress.add_task("Scanning...", total=None)
                
                # Run the scan
                discovered = await self.scanner.scan(target)
                
                # Update progress
                progress.update(scan_task, description=f"Found {len(discovered)} domains")
            
            # Process discovered domains with progress indicator
            if discovered:
                console.print(f"[bold green]Found {len(discovered)} domains in passive scan[/bold green]")
                
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[bold blue]Validating subdomains...[/bold blue]"),
                    BarColumn(),
                    TimeElapsedColumn(),
                    console=console
                ) as progress:
                    # Create filtered list of new domains
                    domains_to_process = [d for d in discovered if d not in self.discovered]
                    
                    # Create progress bar with known total
                    validation_task = progress.add_task(
                        "Validating...", 
                        total=len(domains_to_process)
                    )
                    
                    # Process each domain and update progress
                    for domain in domains_to_process:
                        await self._process_subdomain(domain, "PASSIVE")
                        progress.update(validation_task, advance=1, description=f"Processed {domain}")
            
            # Summarize results
            duration = (datetime.utcnow() - start_time).total_seconds()
            
            # Count statistics
            total_count = len(self.results)
            live_count = sum(1 for r in self.results if r.get('is_alive', False))
            
            # Display summary panel
            console.print()
            console.print(Panel(
                f"Duration: [bold]{duration:.2f}[/bold] seconds\n"
                f"Total subdomains: [bold]{total_count}[/bold]\n"
                f"Live subdomains: [bold green]{live_count}[/bold green]\n"
                f"Dead subdomains: [bold red]{total_count - live_count}[/bold red]",
                title="Discovery Results",
                border_style="green"
            ))
            
            # Display detailed results table
            if self.results:
                table = Table(title="Subdomain Details")
                table.add_column("Domain", style="cyan")
                table.add_column("Status", style="bold")
                table.add_column("HTTP", justify="right")
                table.add_column("IPs", justify="right")
                table.add_column("Takeover?")
                
                for result in self.results:
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
            
            return self.results

        except asyncio.CancelledError:
            console.print("[bold red]Discovery cancelled - saving discovered subdomains...[/bold red]")
            self.logger.info("Discovery cancelled - ensuring all subdomains are saved")
            
            # Make sure all discovered subdomains are saved to the database
            for result in self.results:
                try:
                    # This will save each subdomain using the existing repository
                    await self.repository.save(result)
                except Exception as e:
                    self.logger.error(f"Error saving {result['domain']} during cancellation: {str(e)}")
            
            # Display partial results
            duration = (datetime.utcnow() - start_time).total_seconds()
            console.print(Panel(
                f"[bold yellow]Partial results saved to database[/bold yellow]\n"
                f"Duration before cancel: [bold]{duration:.2f}[/bold] seconds\n"
                f"Subdomains discovered: [bold]{len(self.results)}[/bold]",
                title="Cancelled Discovery",
                border_style="yellow"
            ))
            
            raise
            
        except Exception as e:
            console.print(f"[bold red]Discovery failed: {str(e)}[/bold red]")
            self.logger.error(f"Discovery failed: {str(e)}", exc_info=True)
            raise

    async def _process_subdomain(self, domain: str, source: str):
        """Validate and store a discovered subdomain"""
        if domain in self.discovered:
            return
            
        self.discovered.add(domain)
        
        try:
            # Run validation checks with better error handling
            results = await asyncio.gather(
                self.network.resolve_domain(domain),
                self.network.probe_http(domain),
                self.network.check_takeover_vulnerability(domain),
                return_exceptions=True  # Important! This prevents one failure from stopping others
            )
            
            # Process results, checking for exceptions
            ips = [] if isinstance(results[0], Exception) else results[0]
            
            status = None
            if not isinstance(results[1], Exception):
                status = results[1][0] if results[1] else None
                
            takeover = False
            if not isinstance(results[2], Exception):
                takeover = results[2]
            
            # Prepare result with proper typing
            result = {
                'domain': domain,
                'source': source,
                'ip_addresses': ips,
                'is_alive': bool(ips),
                'http_status': status,
                'is_takeover_candidate': takeover,
                'discovery_time': datetime.utcnow(),
                'last_checked': None
            }
            
            # Add to results collection first
            self.results.append(result)
            
            # Save to database immediately for each subdomain
            try:
                await self.repository.save(result)
            except Exception as e:
                self.logger.error(f"Failed to save {domain} to database: {str(e)}")
                # Continue anyway since we'll retry on cancellation
            
            # Log validation results with color
            is_alive = bool(ips)
            status_color = "green" if is_alive else "red"
            domain_status = f"[{status_color}]{domain}[/{status_color}]"
            
            self.logger.info(f"Validated {domain_status} - HTTP: {status}, IPs: {len(ips)}")
            
        except asyncio.CancelledError:
            self.logger.info(f"Processing of {domain} was cancelled")
            raise
        except Exception as e:
            console.print(f"[bold red]Failed to process {domain}: {str(e)}[/bold red]")
            self.logger.error(f"Failed to process {domain}: {str(e)}")