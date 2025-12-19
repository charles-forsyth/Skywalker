import json
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

    def get_display_name(self, email: str) -> str:
        """Returns the display name if found in the local cache, else empty string."""
        return self.cache.get(email, "")
