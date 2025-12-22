from tenacity import stop_after_attempt, wait_exponential

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