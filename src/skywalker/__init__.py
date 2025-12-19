import warnings

# Suppress Google SDK FutureWarning messages about Python 3.10 deprecation
# These clutter the CLI output on systems using Python 3.10.
warnings.filterwarnings("ignore", category=FutureWarning, module="google.api_core")
warnings.filterwarnings("ignore", category=FutureWarning, module="google.cloud")
