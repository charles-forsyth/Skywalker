from google.cloud import compute_v1
from tenacity import retry

from ..core import RETRY_CONFIG, memory
from ..schemas.network import (
    GCPVPC,
    GCPAddress,
    GCPFirewallRule,
    GCPNetworkReport,
    GCPSubnet,
)


@retry(**RETRY_CONFIG)  # type: ignore[call-overload, untyped-decorator]
def get_network_report(project_id: str) -> GCPNetworkReport:
    """
    Scans Networking resources: Firewalls, VPCs, Subnets, and Static IPs.
    """
    report = GCPNetworkReport()

    # 1. Firewalls (Global)
    fw_client = compute_v1.FirewallsClient()
    for fw in fw_client.list(project=project_id):
        ports = []
        # Rules can have 'allowed' or 'denied'
        items = fw.allowed or fw.denied or []
        for item in items:
            # Use getattr for I_p_protocol as it varies by version
            p_str = getattr(item, "I_p_protocol", getattr(item, "IP_protocol", "unknown"))
            if item.ports:
                p_str += f":{','.join(item.ports)}"
            ports.append(p_str)

        report.firewalls.append(
            GCPFirewallRule(
                name=fw.name,
                network=fw.network.split("/")[-1],
                direction=fw.direction,
                priority=fw.priority,
                action="ALLOW" if fw.allowed else "DENY",
                source_ranges=list(fw.source_ranges) if fw.source_ranges else [],
                allowed_ports=ports,
                target_tags=list(fw.target_tags) if fw.target_tags else [],
            )
        )

    # 2. VPCs & Subnets (Global / Regional Aggregation)
    net_client = compute_v1.NetworksClient()
    for net in net_client.list(project=project_id):
        # Networks list subnets as URLs.
        vpc = GCPVPC(name=net.name)
        report.vpcs.append(vpc)

    # 3. Subnets (Aggregated List)
    subnet_client = compute_v1.SubnetworksClient()
    # agg_list returns a dictionary-like object keyed by region
    for region, subnet_list in subnet_client.aggregated_list(project=project_id):
        if not subnet_list.subnetworks:
            continue

        for sn in subnet_list.subnetworks:
            # Find the parent VPC in our report to attach it
            network_name = sn.network.split("/")[-1]
            found_vpc = next((v for v in report.vpcs if v.name == network_name), None)
            if found_vpc:
                found_vpc.subnets.append(
                    GCPSubnet(
                        name=sn.name,
                        region=region.split("/")[-1],
                        cidr_range=sn.ip_cidr_range,
                        private_google_access=sn.private_ip_google_access,
                        flow_logs=bool(sn.enable_flow_logs),
                    )
                )

    # 4. Addresses (Static IPs) - Aggregated List
    addr_client = compute_v1.AddressesClient()
    for region, addr_list in addr_client.aggregated_list(project=project_id):
        if not addr_list.addresses:
            continue

        for addr in addr_list.addresses:
            report.addresses.append(
                GCPAddress(
                    name=addr.name,
                    address=addr.address,
                    region=region.split("/")[-1],
                    status=str(addr.status),
                    user=addr.users[0].split("/")[-1] if addr.users else None,
                )
            )

    return report
