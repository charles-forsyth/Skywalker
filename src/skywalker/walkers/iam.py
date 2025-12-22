from google.cloud import iam_admin_v1
from google.iam.v1 import iam_policy_pb2
from tenacity import retry

from ..clients import get_iam_client, get_projects_client
from ..core import RETRY_CONFIG
from ..logger import logger
from ..schemas.iam import GCPIAMReport, GCPKey, GCPPolicyBinding, GCPServiceAccount


@retry(**RETRY_CONFIG)  # type: ignore[call-overload, untyped-decorator]
def get_iam_report(project_id: str) -> GCPIAMReport:
    """
    Fetches both Service Account inventory and Project-Level Policy bindings.
    """
    report = GCPIAMReport()

    # 1. Fetch Service Accounts
    iam_client = get_iam_client()
    project_name = f"projects/{project_id}"

    try:
        sa_request = iam_admin_v1.ListServiceAccountsRequest(name=project_name)
        for sa in iam_client.list_service_accounts(request=sa_request):
            # Fetch Keys for this SA
            keys = []
            try:
                key_request = iam_admin_v1.ListServiceAccountKeysRequest(
                    name=f"projects/{project_id}/serviceAccounts/{sa.email}",
                    key_types=[
                        iam_admin_v1.ListServiceAccountKeysRequest.KeyType.USER_MANAGED
                    ],
                )
                for k in iam_client.list_service_account_keys(request=key_request):
                    keys.append(
                        GCPKey(
                            name=k.name.split("/")[-1],
                            key_type=k.key_type.name,
                            valid_after=k.valid_after_time,
                            valid_before=k.valid_before_time,
                        )
                    )
            except Exception as e:
                logger.debug(f"Failed to list keys for SA {sa.email}: {e}")

            report.service_accounts.append(
                GCPServiceAccount(
                    email=sa.email,
                    unique_id=sa.unique_id,
                    display_name=sa.display_name,
                    description=sa.description,
                    disabled=sa.disabled,
                    keys=keys,
                )
            )
    except Exception as e:
        logger.warning(f"Failed to list Service Accounts for {project_id}: {e}")

    # 2. Fetch Project Policy (Bindings)
    try:
        rm_client = get_projects_client()
        policy_request = iam_policy_pb2.GetIamPolicyRequest(resource=project_name)
        policy = rm_client.get_iam_policy(request=policy_request)

        for binding in policy.bindings:
            report.policy_bindings.append(
                GCPPolicyBinding(role=binding.role, members=list(binding.members))
            )
    except Exception as e:
        logger.warning(f"Failed to fetch IAM policy for {project_id}: {e}")

    return report