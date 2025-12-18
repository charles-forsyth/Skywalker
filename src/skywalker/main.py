import argparse
import sys
from rich.console import Console

def main():
    parser = argparse.ArgumentParser(description="Skywalker: GCP Audit & Reporting Tool")
    parser.add_argument("--project-id", help="GCP Project ID to scan")
    parser.add_argument("--zone", help="GCP Zone to scan", default="us-west1-b")
    
    args = parser.parse_args()
    
    console = Console()
    console.print(f"[bold green]Skywalker[/bold green] initialized.")
    
    if not args.project_id:
        console.print("[yellow]No project ID provided. Use --help for usage.[/yellow]")
        return

    try:
        from .walker import list_instances
        console.print(f"Scanning project [bold cyan]{args.project_id}[/bold cyan] in zone [bold cyan]{args.zone}[/bold cyan]...")
        instances = list_instances(project_id=args.project_id, zone=args.zone)
        
        console.print(f"Found [bold]{len(instances)}[/bold] instances:")
        for inst in instances:
            console.print(f" - [green]{inst.name}[/green] ({inst.machine_type}) [{inst.status}]")
            
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")

if __name__ == "__main__":
    main()
