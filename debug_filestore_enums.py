from google.cloud import filestore_v1

client = filestore_v1.CloudFilestoreManagerClient()
# Using the known zone
parent = "projects/ucr-research-computing/locations/us-central1-c"

print("Listing instances...")
for instance in client.list_instances(parent=parent):
    print(f"Name: {instance.name}")
    print(f"Tier Raw: {instance.tier} (Type: {type(instance.tier)})")
    try:
        tier_name = filestore_v1.Instance.Tier(instance.tier).name
        print(f"Tier Name (Constructor): {tier_name}")
        print(f"Tier Name (Direct): {instance.tier.name}")
    except Exception as e:
        print(f"Error converting tier: {e}")
        
    print(f"State Raw: {instance.state} (Type: {type(instance.state)})")
    try:
        state_name = filestore_v1.Instance.State(instance.state).name
        print(f"State Name (Constructor): {state_name}")
        print(f"State Name (Direct): {instance.state.name}")
    except Exception as e:
        print(f"Error converting state: {e}")
    print("-" * 20)
