import joblib
from tenacity import stop_after_attempt, wait_exponential

# Shared memory cache
memory = joblib.Memory(location=".cache", verbose=0)

# Shared retry configuration
# usage: @retry(**RETRY_CONFIG)
RETRY_CONFIG = {
    "stop": stop_after_attempt(3),
    "wait": wait_exponential(multiplier=1, min=4, max=10),
}
