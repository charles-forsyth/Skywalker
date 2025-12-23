import logging

from rich.logging import RichHandler


def setup_logger(name: str = "skywalker", level: int = logging.ERROR) -> logging.Logger:
    """Configures and returns a logger with RichHandler."""

    logger = logging.getLogger(name)

    # Avoid adding duplicate handlers if setup is called multiple times

    if not logger.handlers:
        logger.setLevel(level)

        handler = RichHandler(rich_tracebacks=True, markup=True)

        handler.setFormatter(logging.Formatter("%(message)s"))

        logger.addHandler(handler)

    else:
        logger.setLevel(level)

    return logger


# Global logger instance (default to ERROR to reduce noise)


logger = setup_logger(level=logging.ERROR)
