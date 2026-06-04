import csv
import time
from pathlib import Path
from typing import Any

from google.api_core import exceptions as google_exceptions
from google.cloud import monitoring_v3
from tenacity import retry

from ..clients import get_monitoring_client
from ..core import RETRY_CONFIG
from ..logger import logger
from ..schemas.modelusage import GCPModelUsage, GCPProjectModelUsageReport


def load_pricing_info() -> list[dict[str, Any]]:
    """
    Loads pricing structure from the model_prices.csv file if it exists.
    Falls back to a standard baseline dictionary if the file cannot be loaded.
    """
    csv_path = Path("/home/chuck/Projects/nexus/scripts/model_prices.csv")
    pricing: list[dict[str, Any]] = []

    if csv_path.exists():
        try:
            with csv_path.open(encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    pricing.append(
                        {
                            "pattern": row["model_pattern"].strip(),
                            "input": float(row["input_price_per_m"]),
                            "output": float(row["output_price_per_m"]),
                            "blended": float(row["blended_price_per_m"]),
                        }
                    )
        except Exception as e:
            logger.debug(f"Failed to read pricing CSV from {csv_path}: {e}")

    if not pricing:
        # Standard representative pricing baseline as fallback
        pricing = [
            {
                "pattern": "gemini-1.5-flash-8b",
                "input": 0.0375,
                "output": 0.15,
                "blended": 0.075,
            },
            {
                "pattern": "gemini-1.5-flash",
                "input": 0.075,
                "output": 0.30,
                "blended": 0.15,
            },
            {
                "pattern": "gemini-1.5-pro",
                "input": 1.25,
                "output": 5.00,
                "blended": 2.50,
            },
            {
                "pattern": "gemini-2.5-pro",
                "input": 1.25,
                "output": 10.00,
                "blended": 2.50,
            },
            {
                "pattern": "gemini-2.5-flash",
                "input": 0.30,
                "output": 2.50,
                "blended": 0.50,
            },
            {
                "pattern": "gemini-3.1-pro",
                "input": 2.00,
                "output": 12.00,
                "blended": 4.00,
            },
            {
                "pattern": "gemini-3.1-flash-lite",
                "input": 0.25,
                "output": 1.50,
                "blended": 0.40,
            },
            {
                "pattern": "gemini-3.5-flash",
                "input": 1.50,
                "output": 9.00,
                "blended": 3.00,
            },
            {
                "pattern": "gemini-3-flash",
                "input": 0.50,
                "output": 3.00,
                "blended": 1.00,
            },
            {
                "pattern": "claude-3-5-haiku",
                "input": 0.80,
                "output": 4.00,
                "blended": 1.60,
            },
            {
                "pattern": "claude-3-haiku",
                "input": 0.25,
                "output": 1.25,
                "blended": 0.50,
            },
            {
                "pattern": "claude-haiku-4-5",
                "input": 1.00,
                "output": 5.00,
                "blended": 2.00,
            },
            {"pattern": "opus-4", "input": 5.00, "output": 25.00, "blended": 15.00},
            {"pattern": "opus", "input": 15.00, "output": 75.00, "blended": 45.00},
            {"pattern": "sonnet", "input": 3.00, "output": 15.00, "blended": 6.00},
            {"pattern": "haiku", "input": 1.00, "output": 4.00, "blended": 1.25},
            {
                "pattern": "grok-4.1-fast",
                "input": 0.20,
                "output": 0.50,
                "blended": 0.25,
            },
            {"pattern": "grok-4.20", "input": 2.00, "output": 6.00, "blended": 3.00},
            {"pattern": "grok-4.3", "input": 1.25, "output": 2.50, "blended": 1.50},
            {
                "pattern": "medlm-large",
                "input": 1.25,
                "output": 5.00,
                "blended": 2.50,
            },
            {
                "pattern": "medlm-medium",
                "input": 0.075,
                "output": 0.30,
                "blended": 0.15,
            },
            {"pattern": "llama-3-70b", "input": 0.80, "output": 2.40, "blended": 1.20},
            {"pattern": "llama-3-8b", "input": 0.15, "output": 0.60, "blended": 0.25},
            {"pattern": "gemini", "input": 1.00, "output": 4.00, "blended": 1.00},
            {"pattern": "default", "input": 0.00, "output": 0.00, "blended": 0.00},
        ]
    return pricing


def find_model_pricing(model_id: str, pricing: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Finds matching pricing rule by matching the pattern as a substring of model_id.
    """
    model_id_lower = model_id.lower()
    for p in pricing:
        if p["pattern"] == "default":
            continue
        if p["pattern"] in model_id_lower:
            return p
    # Fallback to default
    for p in pricing:
        if p["pattern"] == "default":
            return p
    return {"pattern": "default", "input": 0.0, "output": 0.0, "blended": 0.0}


@retry(**RETRY_CONFIG)  # type: ignore[call-overload, untyped-decorator]
def get_model_usage_report(
    project_id: str, days: int = 30
) -> GCPProjectModelUsageReport:
    """
    Queries Cloud Monitoring metrics for model invocations and token count,
    matches with local model prices, and builds an aggregated usage/cost report.
    """
    report = GCPProjectModelUsageReport(project_id=project_id)

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

    invocations: dict[str, int] = {}
    input_tokens: dict[str, int] = {}
    output_tokens: dict[str, int] = {}
    publishers: dict[str, str] = {}

    # 1. Fetch Invocations (Requests)
    try:
        inv_filter = (
            'metric.type = "aiplatform.googleapis.com/publisher/online_serving/'
            'model_invocation_count"'
        )
        pages = monitoring_client.list_time_series(
            request={
                "name": monitoring_scope,
                "filter": inv_filter,
                "interval": interval,
                "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
                "aggregation": monitoring_v3.Aggregation(
                    {
                        "alignment_period": {"seconds": days * 86400},
                        "per_series_aligner": (
                            monitoring_v3.Aggregation.Aligner.ALIGN_SUM
                        ),
                        "cross_series_reducer": (
                            monitoring_v3.Aggregation.Reducer.REDUCE_SUM
                        ),
                        "group_by_fields": [
                            "resource.label.model_user_id",
                            "resource.label.publisher",
                        ],
                    }
                ),
            }
        )
        for ts in pages:
            model_user_id = ts.resource.labels.get("model_user_id", "")
            publisher = ts.resource.labels.get("publisher", "")
            if not model_user_id:
                continue

            points_sum = sum(
                p.value.int64_value
                if p.value.int64_value is not None
                else p.value.double_value
                for p in ts.points
            )
            if points_sum <= 0:
                continue

            invocations[model_user_id] = invocations.get(model_user_id, 0) + int(
                points_sum
            )
            if publisher:
                publishers[model_user_id] = publisher
    except (
        google_exceptions.ServiceUnavailable,
        google_exceptions.InternalServerError,
        google_exceptions.TooManyRequests,
        google_exceptions.GatewayTimeout,
    ):
        raise
    except Exception as e:
        logger.debug(f"Failed to query model invocations for {project_id}: {e}")

    # 2. Fetch Token Counts
    try:
        tok_filter = (
            'metric.type = "aiplatform.googleapis.com/publisher/online_serving/'
            'token_count"'
        )
        pages = monitoring_client.list_time_series(
            request={
                "name": monitoring_scope,
                "filter": tok_filter,
                "interval": interval,
                "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
                "aggregation": monitoring_v3.Aggregation(
                    {
                        "alignment_period": {"seconds": days * 86400},
                        "per_series_aligner": (
                            monitoring_v3.Aggregation.Aligner.ALIGN_SUM
                        ),
                        "cross_series_reducer": (
                            monitoring_v3.Aggregation.Reducer.REDUCE_SUM
                        ),
                        "group_by_fields": [
                            "resource.label.model_user_id",
                            "resource.label.publisher",
                            "metric.label.type",
                        ],
                    }
                ),
            }
        )
        for ts in pages:
            model_user_id = ts.resource.labels.get("model_user_id", "")
            publisher = ts.resource.labels.get("publisher", "")
            token_type = ts.metric.labels.get("type", "")  # "input" or "output"
            if not model_user_id:
                continue

            points_sum = sum(
                p.value.int64_value
                if p.value.int64_value is not None
                else p.value.double_value
                for p in ts.points
            )
            if points_sum <= 0:
                continue

            if token_type == "input":
                input_tokens[model_user_id] = input_tokens.get(model_user_id, 0) + int(
                    points_sum
                )
            elif token_type == "output":
                output_tokens[model_user_id] = output_tokens.get(
                    model_user_id, 0
                ) + int(points_sum)

            if publisher:
                publishers[model_user_id] = publisher
    except (
        google_exceptions.ServiceUnavailable,
        google_exceptions.InternalServerError,
        google_exceptions.TooManyRequests,
        google_exceptions.GatewayTimeout,
    ):
        raise
    except Exception as e:
        logger.debug(f"Failed to query token count metrics for {project_id}: {e}")

    # 3. Assemble report
    all_models = (
        set(invocations.keys()) | set(input_tokens.keys()) | set(output_tokens.keys())
    )
    pricing_info = load_pricing_info()

    usages_list: list[GCPModelUsage] = []
    total_requests = 0
    total_input = 0
    total_output = 0
    total_cost = 0.0

    for m_id in sorted(all_models):
        reqs = invocations.get(m_id, 0)
        in_t = input_tokens.get(m_id, 0)
        out_t = output_tokens.get(m_id, 0)

        pricing = find_model_pricing(m_id, pricing_info)
        cost = (in_t / 1000000.0) * pricing["input"] + (out_t / 1000000.0) * pricing[
            "output"
        ]

        usages_list.append(
            GCPModelUsage(
                model_id=m_id,
                publisher=publishers.get(m_id, "unknown"),
                request_count=reqs,
                input_tokens=in_t,
                output_tokens=out_t,
                estimated_cost=round(cost, 4),
            )
        )

        total_requests += reqs
        total_input += in_t
        total_output += out_t
        total_cost += cost

    # Sort by cost descending
    usages_list.sort(key=lambda u: u.estimated_cost, reverse=True)

    report.usages = usages_list
    report.total_requests = total_requests
    report.total_input_tokens = total_input
    report.total_output_tokens = total_output
    report.total_estimated_cost = round(total_cost, 2)

    return report
