from google.cloud import asset_v1

client = asset_v1.AssetServiceClient()
scope = "organizations/586321020548"

print(f"Searching scope: {scope}...")
response = client.search_all_resources(
    request={
        "scope": scope,
        "asset_types": ["compute.googleapis.com/Instance"],
    }
)

count = 0
for resource in response:
    count += 1
    print(f"[{count}] Name: {resource.display_name} | ID: {resource.additional_attributes.get('id')} | Project: {resource.project}")
    if count >= 10: break

print(f"Total found in first page: {count}")