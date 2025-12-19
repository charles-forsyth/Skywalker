import warnings
from pathlib import Path

import joblib
from joblib.memory import JobLibCollisionWarning
from tenacity import stop_after_attempt, wait_exponential

# Suppress JobLib collision warnings caused by tenacity wrapping
warnings.simplefilter("ignore", JobLibCollisionWarning)

# Shared memory cache
# Use an absolute path so the cache is shared regardless of CWD
cache_dir = Path.home() / ".cache" / "skywalker"
memory = joblib.Memory(location=str(cache_dir), verbose=0)

# Shared retry configuration
# usage: @retry(**RETRY_CONFIG)
RETRY_CONFIG = {
    "stop": stop_after_attempt(3),
    "wait": wait_exponential(multiplier=1, min=4, max=10),
}

# Standard US Regions for auditing
# These cover the vast majority of UCR/Research workloads.
STANDARD_REGIONS = [
    "us-central1",
    "us-west1",
    "us-east1",
    "us-east4",
    "us-west2",
    "us-west4",
]

# Standard suffixes to generate zones from regions
# e.g. us-central1 -> us-central1-a, us-central1-b, ...
ZONE_SUFFIXES = ["a", "b", "c", "f"]
