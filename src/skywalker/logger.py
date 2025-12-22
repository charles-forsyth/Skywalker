import logging

from rich.logging import RichHandler


def setup_logger(name: str = "skywalker") -> logging.Logger:
    """Configures and returns a logger with RichHandler."""
    logger = logging.getLogger(name)

    # Avoid adding duplicate handlers if setup is called multiple times
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = RichHandler(rich_tracebacks=True, markup=True)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)

    return logger


# Global logger instance
logger = setup_logger()
