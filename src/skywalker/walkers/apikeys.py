import time
from typing import Any

from google.api_core import exceptions as google_exceptions
from google.cloud import monitoring_v3
from googleapiclient.errors import HttpError
from tenacity import retry

from ..clients import get_apikeys_client, get_monitoring_client
from ..core import RETRY_CONFIG
from ..logger import logger
from ..schemas.apikeys import GCPAPIKey, GCPAPIKeyUsage, GCPProjectAPIKeysReport

# Costs per 1,000 requests for major APIs (standard representative rates)
API_COSTS = {
    "geocoding-backend.googleapis.com": 5.00,
    "places-backend.googleapis.com": 17.00,
    "maps-backend.googleapis.com": 7.00,
    "translate.googleapis.com": 20.00,
    "vision.googleapis.com": 1.50,
    "texttospeech.googleapis.com": 4.00,
    "speech.googleapis.com": 24.00,
    "directions-backend.googleapis.com": 5.00,
    "distance-matrix-backend.googleapis.com": 5.00,
    "elevation-backend.googleapis.com": 5.00,
    "roads.googleapis.com": 5.00,
    "timezone-backend.googleapis.com": 5.00,
    "maps-embed-backend.googleapis.com": 0.00,  # Free
    "static-maps-backend.googleapis.com": 2.00,
    "street-view-pixels-backend.googleapis.com": 7.00,
}
DEFAULT_API_COST = 1.00  # $1.00 per 1000 requests


@retry(**RETRY_CONFIG)  # type: ignore[call-overload, untyped-decorator]
def get_api_keys_report(project_id: str, days: int = 30) -> GCPProjectAPIKeysReport:
    """
    Performs a deep audit of API Keys in the project,
    aggregating metadata, restrictions, historical usages, and costs.
    """
    report = GCPProjectAPIKeysReport(project_id=project_id)

    # 1. Fetch Key Metadata via API Keys API
    client = get_apikeys_client()
    parent = f"projects/{project_id}/locations/global"

    keys_list: list[dict[str, Any]] = []
    try:
        request = client.projects().locations().keys().list(parent=parent)
        response = request.execute()
        keys_list = response.get("keys", [])
    except HttpError as e:
        if e.resp.status in [429, 500, 503, 504]:
            raise
        if e.resp.status == 403:
            logger.warning(
                f"Permission denied listing API Keys for {project_id} "
                "(API Keys API may be disabled or missing IAM roles)."
            )
        else:
            logger.warning(f"Failed to list API Keys for {project_id}: {e}")
    except Exception as e:
        logger.warning(f"Unexpected error listing API Keys for {project_id}: {e}")

    # Process each key metadata
    for key_data in keys_list:
        name = key_data.get("name", "")
        uid = key_data.get("uid", "")
        display_name = key_data.get("displayName", "Unnamed Key")
        created_at = key_data.get("createTime", "")

        # Key restrictions
        restrictions_raw = key_data.get("restrictions", {})
        restrictions: dict[str, list[str]] = {}
        is_restricted = False

        if "apiTargets" in restrictions_raw:
            is_restricted = True
            targets = []
            for target in restrictions_raw["apiTargets"]:
                service = target.get("service")
                methods = target.get("methods", [])
                targets.append(
                    f"{service} ({', '.join(methods)})" if methods else service
                )
            restrictions["API Targets (Scoped)"] = targets

        if "browserKeyRestrictions" in restrictions_raw:
            is_restricted = True
            restrictions["HTTP Referrers"] = restrictions_raw[
                "browserKeyRestrictions"
            ].get("allowedReferrers", [])

        if "serverKeyRestrictions" in restrictions_raw:
            is_restricted = True
            restrictions["IP Addresses"] = restrictions_raw[
                "serverKeyRestrictions"
            ].get("allowedIps", [])

        if "androidKeyRestrictions" in restrictions_raw:
            is_restricted = True
            allowed_apps = []
            for app in restrictions_raw["androidKeyRestrictions"].get(
                "allowedApplications", []
            ):
                allowed_apps.append(
                    f"{app.get('packageName')} (SHA1: {app.get('sha1Fingerprint')})"
                )
            restrictions["Android Apps"] = allowed_apps

        if "iosKeyRestrictions" in restrictions_raw:
            is_restricted = True
            restrictions["iOS Bundles"] = restrictions_raw["iosKeyRestrictions"].get(
                "allowedBundleIds", []
            )

        # Try to retrieve masked key string
        masked_key = None
        try:
            get_str_req = client.projects().locations().keys().getKeyString(name=name)
            get_str_resp = get_str_req.execute()
            key_string = get_str_resp.get("keyString", "")
            if key_string:
                masked_key = f"{key_string[:6]}...{key_string[-6:]}"
        except HttpError as e:
            if e.resp.status in [429, 500, 503, 504]:
                raise
            # Fallback to masking the UID
            masked_key = f"Key-{uid[:8]}"
        except Exception:
            masked_key = f"Key-{uid[:8]}"

        report.keys.append(
            GCPAPIKey(
                name=name,
                uid=uid,
                display_name=display_name,
                created_at=created_at,
                restrictions=restrictions,
                is_restricted=is_restricted,
                masked_key=masked_key,
            )
        )

    # 2. Fetch Usage and Costs via Monitoring API
    monitoring_client = get_monitoring_client()
    monitoring_scope = f"projects/{project_id}"

    now = time.time()
    seconds = int(now)
    start_seconds = seconds - (days * 86400)

    interval = monitoring_v3.TimeInterval(
        {
            "end_time": {"seconds": seconds, "nanos": 0},
            "start_time": {"seconds": start_seconds, "nanos": 0},
        }
    )

    filter_str = (
        'metric.type = "serviceruntime.googleapis.com/api/request_count" '
        'AND resource.type = "consumed_api"'
    )
    alignment_period = {"seconds": days * 86400}
    aggregation = monitoring_v3.Aggregation(
        {
            "alignment_period": alignment_period,
            "per_series_aligner": monitoring_v3.Aggregation.Aligner.ALIGN_SUM,
            "cross_series_reducer": monitoring_v3.Aggregation.Reducer.REDUCE_SUM,
            "group_by_fields": [
                "metric.label.credential_id",
                "resource.label.service",
            ],
        }
    )

    usages_map: dict[str, list[GCPAPIKeyUsage]] = {}
    try:
        pages = monitoring_client.list_time_series(
            request={
                "name": monitoring_scope,
                "filter": filter_str,
                "interval": interval,
                "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
                "aggregation": aggregation,
            }
        )
        for ts in pages:
            credential_id = ts.metric.labels.get("credential_id", "")
            service = ts.resource.labels.get("service", "")

            if not credential_id or not service:
                continue

            # Calculate total usage over the period
            points_sum = 0
            for pt in ts.points:
                points_sum += int(
                    pt.value.int64_value
                    if pt.value.int64_value is not None
                    else pt.value.double_value
                )

            if points_sum <= 0:
                continue

            # Estimate cost
            cost_rate = API_COSTS.get(service, DEFAULT_API_COST)
            estimated_cost = (points_sum / 1000.0) * cost_rate

            usage_record = GCPAPIKeyUsage(
                service=service,
                request_count=points_sum,
                estimated_cost=round(estimated_cost, 4),
            )

            usages_map.setdefault(credential_id, []).append(usage_record)

            report.total_requests += points_sum
            report.total_estimated_cost += estimated_cost

    except (
        google_exceptions.ServiceUnavailable,
        google_exceptions.InternalServerError,
        google_exceptions.TooManyRequests,
        google_exceptions.GatewayTimeout,
    ):
        raise
    except Exception as e:
        logger.debug(f"Failed to fetch API key usage metric for {project_id}: {e}")

    # Normalize the usage matching (map credential_id back to actual key representation)
    normalized_usages: dict[str, list[GCPAPIKeyUsage]] = {}
    for cred_id, records in usages_map.items():
        # Match credential ID which could be 'apikey:UUID',
        # 'apikey:AIzaSy...' or raw 'UUID'
        matched_key_id = cred_id
        clean_cred = cred_id.replace("apikey:", "")

        for key in report.keys:
            if clean_cred == key.uid or clean_cred == key.name.split("/")[-1]:
                matched_key_id = f"{key.display_name} ({key.masked_key or key.uid[:8]})"
                break
        else:
            if clean_cred.startswith("AIzaSy"):
                matched_key_id = f"Key ({clean_cred[:6]}...{clean_cred[-6:]})"
            else:
                matched_key_id = f"Credential ({clean_cred[:8]})"

        normalized_usages[matched_key_id] = sorted(
            records, key=lambda x: x.request_count, reverse=True
        )

    report.usages = normalized_usages
    report.total_estimated_cost = round(report.total_estimated_cost, 2)
    return report
