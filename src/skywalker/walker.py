import joblib
from tenacity import retry, stop_after_attempt, wait_exponential
from google.cloud import compute_v1
from typing import List
from .models import GCPComputeInstance

# Setup simple memory cache
memory = joblib.Memory(location=".cache", verbose=0)

@memory.cache
@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
def list_instances(project_id: str, zone: str) -> List[GCPComputeInstance]:
    """
    Lists all instances in a given zone for a project.
    Cached by joblib and retried by tenacity on failure.
    """
    # Note: Authentication is handled by google-auth automatically using environment variables
    # or gcloud default credentials.
    instance_client = compute_v1.InstancesClient()
    request = compute_v1.ListInstancesRequest(project=project_id, zone=zone)
    
    instances = []
    
    # The client library handles pagination automatically when iterating
    for instance in instance_client.list(request=request):
        # Clean machine type URL to just the type name
        # e.g., https://www.googleapis.com/compute/v1/projects/my-project/zones/us-central1-a/machineTypes/n1-standard-1
        machine_type_clean = instance.machine_type.split('/')[-1] if instance.machine_type else "unknown"
        
        # Parse timestamp string to datetime if necessary.
        # instance.creation_timestamp is an ISO 8601 string from the API.
        
        instances.append(GCPComputeInstance(
            name=instance.name,
            id=str(instance.id),
            status=instance.status,
            machine_type=machine_type_clean,
            zone=zone,
            creation_timestamp=instance.creation_timestamp,
            labels=dict(instance.labels) if instance.labels else {}
        ))
        
    return instances
