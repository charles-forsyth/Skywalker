from tenacity import retry

from ..clients import (
    get_addresses_client,
    get_firewalls_client,
    get_networks_client,
    get_subnetworks_client,
)
from ..core import RETRY_CONFIG
from ..logger import logger
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
    try:
        fw_client = get_firewalls_client()
        for fw in fw_client.list(project=project_id):
            ports = []
            # Rules can have 'allowed' or 'denied'
            items = fw.allowed or fw.denied or []
            for item in items:
                p_str = str(
                    getattr(
                        item, "I_p_protocol", getattr(item, "IP_protocol", "unknown")
                    )
                )
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
    except Exception as e:
        logger.warning(f"Failed to list firewalls for {project_id}: {e}")

    # 2. VPCs & Subnets (Global / Regional Aggregation)
    try:
        net_client = get_networks_client()
        for net in net_client.list(project=project_id):
            vpc = GCPVPC(name=net.name)
            report.vpcs.append(vpc)
    except Exception as e:
        logger.warning(f"Failed to list networks for {project_id}: {e}")

    # 3. Subnets (Aggregated List)
    try:
        subnet_client = get_subnetworks_client()
        for region, subnet_list in subnet_client.aggregated_list(project=project_id):
            if not subnet_list.subnetworks:
                continue

            for sn in subnet_list.subnetworks:
                network_name = sn.network.split("/")[-1]
                found_vpc = next(
                    (v for v in report.vpcs if v.name == network_name), None
                )
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
    except Exception as e:
        logger.warning(f"Failed to list subnets for {project_id}: {e}")

    # 4. Addresses (Static IPs) - Aggregated List
    try:
        addr_client = get_addresses_client()
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
    except Exception as e:
        logger.warning(f"Failed to list static IPs for {project_id}: {e}")

    return report
