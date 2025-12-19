import json
import sys
from pathlib import Path

from rich.console import Console

console = Console(stderr=True)


class UserResolver:
    def __init__(self) -> None:
        self.config_dir = Path.home() / ".config" / "skywalker"
        self.cache_file = self.config_dir / "users.json"
        self.cache: dict[str, str] = {}
        self._load_cache()

    def _load_cache(self) -> None:
        if self.cache_file.exists():
            try:
                with self.cache_file.open("r") as f:
                    self.cache = json.load(f)
            except Exception:
                self.cache = {}

    def _save_cache(self) -> None:
        self.config_dir.mkdir(parents=True, exist_ok=True)
        try:
            with self.cache_file.open("w") as f:
                json.dump(self.cache, f, indent=2)
        except Exception as e:
            console.print(f"[yellow]Warning: Could not save user cache: {e}[/yellow]")

    def get_display_name(self, email: str, interactive: bool = False) -> str:
        if email in self.cache:
            return self.cache[email]

        if interactive and sys.stdin.isatty():
            console.print(f"[yellow]Unknown user found in IAM policy: {email}[/yellow]")
            prompt = (
                f"Enter display name for [bold]{email}[/bold] "
                "(or press Enter to skip): "
            )
            name = console.input(prompt).strip()
            if name:
                self.cache[email] = name
                self._save_cache()
                return name

        return ""
