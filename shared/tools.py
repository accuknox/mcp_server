"""
Tool Implementations
Shared between stdio and HTTP servers
"""

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
            icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(severity, "⚪")
            result += f"   {icon} {severity}: {count}\n"
        result += "\n"
    
    if llm_issues:
        result += "LLM Model Issues:\n"
        for issue in llm_issues:
            severity = issue.get("vulnerability__risk_factor", "Unknown")
            count = issue.get("count", 0)
            icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(severity, "⚪")
            result += f"   {icon} {severity}: {count}\n"
        result += "\n"
    
    if dataset_issues:
        result += "Dataset Issues:\n"
        for issue in dataset_issues:
            severity = issue.get("vulnerability__risk_factor", "Unknown")
            count = issue.get("count", 0)
            icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(severity, "⚪")
            result += f"   {icon} {severity}: {count}\n"
    
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
) -> str:
    """Search assets tool implementation"""
    
    try:
        if return_type == "count":
            data = await client.fetch_assets(
                asset_id=asset_id, type_name=type_name, type_category=type_category,
                label_name=label_name, region=region, cloud_provider=cloud_provider,
                page_size=1,
            )
            return f"Total assets: {data.get('count', 0)}"
        
        data = await client.fetch_assets(
            asset_id=asset_id, type_name=type_name, type_category=type_category,
            label_name=label_name, region=region, cloud_provider=cloud_provider,
            page_size=limit,
        )
        
        return format_asset_list(data.get("results", []), data.get("count", 0), detailed)
    
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
