"""
Tool Implementations
Shared between stdio and HTTP servers
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx

from .api import AccuKnoxClient


def format_asset_list(assets: list, total_count: int, detailed: bool = False) -> str:
    """Format asset list for display"""
    if not assets:
        return "No assets found."

    result = f"Found {len(assets)} assets (Total: {total_count}):\n\n"

    for idx, asset in enumerate(assets, 1):
        result += f"{'='*70}\nAsset #{idx}\n{'='*70}\n"

        name = asset.get("name", "Unnamed")
        asset_id = asset.get("id", "N/A")
        asset_type = asset.get("type", {})

        if isinstance(asset_type, dict):
            type_name = asset_type.get("name", "Unknown")
            type_category = asset_type.get("category", "")
        else:
            type_name = "Unknown"
            type_category = ""

        region = asset.get("region", "N/A")

        result += f"Name: {name}\n"
        result += f"ID: {asset_id}\n"
        result += f"Type: {type_name}"
        if type_category:
            result += f" (Category: {type_category})"
        result += f"\nRegion: {region}\n"

        if detailed or "vulnerabilities" in asset:
            label = asset.get("label", {})
            if isinstance(label, dict):
                result += f"Label: {label.get('name', 'N/A')}\n"

            vulns = asset.get("vulnerabilities", {})
            if vulns:
                vuln_list = [f"{k}: {v}" for k, v in vulns.items() if v > 0]
                if vuln_list:
                    result += f"Vulnerabilities: {', '.join(vuln_list)}\n"

        result += "\n"

    return result


def format_model_vulnerabilities(data: dict) -> str:
    """Format model vulnerabilities"""

    ml_issues = data.get("ml_model_issues", [])
    llm_issues = data.get("llm_model_issues", [])
    dataset_issues = data.get("dataset_issues", [])

    ml_total = data.get("ml_total", 0)
    llm_total = data.get("llm_total", 0)
    dataset_total = data.get("dataset_total", 0)
    total = data.get("total", 0)

    result = " AI/ML Model Security Vulnerabilities\n"
    result += "=" * 70 + "\n\n"
    result += f"   Summary: {total} total issues\n"
    result += f"   ML Models: {ml_total}\n"
    result += f"   LLM Models: {llm_total}\n"
    result += f"   Datasets: {dataset_total}\n\n"

    if ml_issues:
        result += " ML Model Issues:\n"
        for issue in ml_issues:
            severity = issue.get("vulnerability__risk_factor", "Unknown")
            count = issue.get("count", 0)
            icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(
                severity,
                "⚪",
            )
            result += f"   {icon} {severity}: {count}\n"
        result += "\n"

    if llm_issues:
        result += "LLM Model Issues:\n"
        for issue in llm_issues:
            severity = issue.get("vulnerability__risk_factor", "Unknown")
            count = issue.get("count", 0)
            icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(
                severity,
                "⚪",
            )
            result += f"   {icon} {severity}: {count}\n"
        result += "\n"

    if dataset_issues:
        result += "Dataset Issues:\n"
        for issue in dataset_issues:
            severity = issue.get("vulnerability__risk_factor", "Unknown")
            count = issue.get("count", 0)
            icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(
                severity,
                "⚪",
            )
            result += f"   {icon} {severity}: {count}\n"

    return result


# def format_model_stats(data: dict) -> str:
#     """Format model deployment statistics"""

#     deployed_data = data.get("data", {}).get("deployed", {})
#     mode_type = data.get("data", {}).get("mode_type", {})

#     deployed_count = deployed_data.get("true", 0)
#     not_deployed_count = deployed_data.get("false", 0)
#     total_models = deployed_count + not_deployed_count

#     llm_count = mode_type.get("LLM", 0)

#     result = " AI Model Deployment Statistics\n"
#     result += "=" * 70 + "\n\n"

#     result += f"   Total Models Tracked: {total_models}\n"
#     result += f"   ✅ Deployed Models:   {deployed_count}\n"
#     result += f"   ❌ Not Deployed:      {not_deployed_count}\n\n"

#     if llm_count > 0:
#         result += f"   Model Types:\n"
#         result += f"   - LLM (Large Language Models): {llm_count}\n"

#     return result

def format_ai_assets_stats(data: dict) -> str:
    """Format AI assets statistics (deployed vs not deployed)"""
    
    # The API response structure:
    # data -> data -> provider -> data -> list of assets
    
    root_data = data.get("data", {})
    # If total_count is not in root_data, we might need to sum it up or it might be missing
    total_count = root_data.get("total_count", 0)
    
    deployed_models = []
    undeployed_models = []
    
    # Iterate through potential providers (keys in root_data)
    for key, value in root_data.items():
        if key == "total_count" or not isinstance(value, dict):
            continue
            
        # Check for 'data' which should be a list of assets
        provider_assets = value.get("data", [])
        if not isinstance(provider_assets, list):
            continue
            
        for node in provider_assets:
            # Use model_name if available, fallback to name, then Unnamed
            name = node.get("model_name") or node.get("name") or "Unnamed"
            
            # Check status for deployment (assuming status=True means deployed)
            # The user JSON showed "status": false
            is_deployed = node.get("status", False)
            
            if is_deployed:
                deployed_models.append(name)
            else:
                undeployed_models.append(name)

    # Recalculate total count if it was 0 but we found models
    found_count = len(deployed_models) + len(undeployed_models)
    if total_count == 0 and found_count > 0:
        total_count = found_count

    result = " AI Model Assets\n"
    result += "=" * 70 + "\n\n"
    result += f"   Total Models Found: {total_count}\n\n"
    
    if deployed_models:
        result += f"Deployed Models ({len(deployed_models)}):\n"
        # Sort for better readability
        for name in sorted(deployed_models):
            result += f"      - {name}\n"
        result += "\n"
        
    if undeployed_models:
        result += f"Undeployed/Other Models ({len(undeployed_models)}):\n"
        # Limit the output of undeployed models if there are too many
        sorted_undeployed = sorted(undeployed_models)
        display_limit = 20
        for name in sorted_undeployed[:display_limit]:
            result += f"      - {name}\n"
        
        if len(undeployed_models) > display_limit:
            result += f"      ... and {len(undeployed_models) - display_limit} more.\n"
    
    return result

async def search_assets_tool(
    client: AccuKnoxClient,
    asset_id: Optional[str] = None,
    type_name: Optional[str] = None,
    type_category: Optional[str] = None,
    label_name: Optional[str] = None,
    region: Optional[str] = None,
    cloud_provider: Optional[str] = None,
    return_type: str = "list",
    limit: int = 10,
    detailed: bool = False,
    deployed: Optional[bool] = None,
    present_on_date_after: Optional[str] = None,
    present_on_date_before: Optional[str] = None,
) -> str:
    """Search assets tool implementation"""

    try:
        # # If requesting deployed models statistics
        # if deployed:
        #     # We can use default timestamps or accept them as args if needed
        #     # For now, using a wide range or letting backend handle defaults if possible
        #     # The user prompt "deployed models" implies current state
        #     # Using the timestamps from the test case as a baseline or current time
        #     import time

        #     now = int(time.time())
        #     two_weeks_ago = now - (14 * 24 * 60 * 60)

        #     data = await client.fetch_model_stats(
        #         last_seen_after=str(two_weeks_ago),
        #         last_seen_before=str(now),
        #     )
        #     return format_model_stats(data)
        # If requesting deployed models statistics
        if deployed is not None:
            # Convert dates to timestamps for the new API
            # from datetime import datetime, timezone
            
            # Helper to convert YYYY-MM-DD to unix timestamp
            def to_ts(date_str: str, end_of_day: bool = False) -> int:
                dt = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                if end_of_day:
                    dt = dt.replace(hour=23, minute=59, second=59)
                return int(dt.timestamp())

            start_ts = to_ts(present_on_date_after)
            end_ts = to_ts(present_on_date_before, end_of_day=True)

            data = await client.fetch_ai_assets(
                start_ts=start_ts,
                end_ts=end_ts,
                cloud_provider=cloud_provider,
                deployed=deployed
            )
            return format_ai_assets_stats(data)


        now = datetime.now()
        # Calculate default time range if not provided (2days window)
        if not present_on_date_after:
            present_on_date_after = (now - timedelta(days=2)).strftime("%Y-%m-%d")
        if not present_on_date_before:
            present_on_date_before = now.strftime("%Y-%m-%d")

        if return_type == "count":
            data = await client.fetch_assets(
                asset_id=asset_id,
                type_name=type_name,
                type_category=type_category,
                label_name=label_name,
                region=region,
                cloud_provider=cloud_provider,
                present_on_date_after=present_on_date_after,
                present_on_date_before=present_on_date_before,
                page_size=1,
            )
            return f"Total assets: {data.get('count', 0)}"

        data = await client.fetch_assets(
            asset_id=asset_id,
            type_name=type_name,
            type_category=type_category,
            label_name=label_name,
            region=region,
            cloud_provider=cloud_provider,
            present_on_date_after=present_on_date_after,
            present_on_date_before=present_on_date_before,
            page_size=limit,
        )

        return format_asset_list(
            data.get("results", []),
            data.get("count", 0),
            detailed,
        )

    except httpx.HTTPStatusError as e:
        return f"API Error: {e.response.status_code}"
    except Exception as e:
        return f"Error: {str(e)}"


async def get_model_vulnerabilities_tool(client: AccuKnoxClient) -> str:
    """Get model vulnerabilities tool implementation"""

    try:
        data = await client.fetch_model_vulnerabilities()
        return format_model_vulnerabilities(data)
    except httpx.HTTPStatusError as e:
        return f"API Error: {e.response.status_code}"
    except Exception as e:
        return f"Error: {str(e)}"
