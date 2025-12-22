from google.cloud import sql_v1beta4

client = sql_v1beta4.SqlInstancesServiceClient()
project_id = "ucr-research-computing"

print(f"Listing SQL instances for {project_id}...")
try:
    response = client.list(project=project_id)
    for instance in response.items:
        print(f"Name: {instance.name}")
        print(f"State: {instance.state}")
        print(f"Tier: {instance.settings.tier}")
        print(f"Disk Size: {instance.settings.data_disk_size_gb}")
        for ip in instance.ip_addresses:
            print(f"  IP: {ip.ip_address} ({ip.type_})")
        print("-" * 20)
except Exception as e:
    print(f"Error: {e}")
