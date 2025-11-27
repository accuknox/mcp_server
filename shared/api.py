"""
AccuKnox API Client
Handles all API interactions with AccuKnox CSPM
"""

import os
from typing import Optional

import httpx
from dotenv import load_dotenv

# https://cspm.demo.accuknox.com/api/v1/assets?page=1&page_size=20&search=&depth=3&ordering=name&label_name=K8SJOB&present_on_date_after=2025-11-22&present_on_date_before=2025-11-24

load_dotenv()


class AccuKnoxClient:
    """Client for AccuKnox CSPM API"""

    def __init__(self):
        self.base_url = os.getenv("ACCUKNOX_BASE_URL", "").rstrip("/")
        self.api_token = os.getenv("ACCUKNOX_API_TOKEN", "")
        self.headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
        }

    async def fetch_assets(
        self,
        asset_id: Optional[str] = None,
        type_name: Optional[str] = None,
        type_category: Optional[str] = None,
        label_name: Optional[str] = None,
        region: Optional[str] = None,
        cloud_provider: Optional[str] = None,
        present_on_date_after: Optional[str] = None,
        present_on_date_before: Optional[str] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> dict:
        """Fetch assets from AccuKnox"""

        endpoint = f"{self.base_url}/api/v1/assets"
        params = {"page": page, "page_size": page_size}

        if asset_id:
            params["id"] = asset_id
        if type_name:
            params["type_name"] = type_name
        if type_category:
            params["type_category"] = type_category
        if label_name:
            params["label_name"] = label_name
        if region:
            params["region"] = region
        if cloud_provider:
            params["cloud_provider"] = cloud_provider
        if present_on_date_after and present_on_date_before:
            params["present_on_date_after"] = present_on_date_after
            params["present_on_date_before"] = present_on_date_before

        async with httpx.AsyncClient() as client:
            response = await client.get(
                endpoint,
                headers=self.headers,
                params=params,
                timeout=30.0,
            )
            response.raise_for_status()
            return response.json()

    async def fetch_model_vulnerabilities(self) -> dict:
        """Fetch model vulnerability summary"""

        endpoint = (
            f"{self.base_url}/api/v1/modelknox/dashboard/ondemand-model-issues-summary/"
        )

        async with httpx.AsyncClient() as client:
            response = await client.get(
                endpoint,
                headers=self.headers,
                params={"page": 1},
                timeout=30.0,
            )
            response.raise_for_status()
            return response.json()

    async def fetch_model_stats(
        self,
        last_seen_after: Optional[str] = None,
        last_seen_before: Optional[str] = None,
    ) -> dict:
        """Fetch model statistics (deployed vs not deployed)"""

        endpoint = f"{self.base_url}/api/v1/modelknox/dashboard/model-stats/"
        params = {}

        if last_seen_after:
            params["last_seen_after"] = last_seen_after
        if last_seen_before:
            params["last_seen_before"] = last_seen_before

        async with httpx.AsyncClient() as client:
            response = await client.get(
                endpoint,
                headers=self.headers,
                params=params,
                timeout=30.0,
            )
            response.raise_for_status()
            return response.json()
    async def fetch_ai_assets(
        self,
        start_ts: int,
        end_ts: int,
        cloud_provider: Optional[str] = None,
        page: int = 1,
        page_size: int = 100
    ) -> dict:
        """Fetch AI assets using the new API endpoint with time-based filtering"""
        endpoint = f"{self.base_url}/api/v1/modelknox/ai-assets/"
        
        # Construct the complex payload
        payload = {
            "asset_type": "model",
            "page": page,
            "page_size": page_size,
            "match": [],
            "optional": [],
            "does_not_match": "",
            "groups_combinator": "OR",
            "advanced_filter": True,
            "groups": [
                {
                    "combinator": "AND",
                    "conditions": [
                        {
                            "target": "label_name",
                            "property": "last_seen",
                            "operator": "in_range",
                            "values": [start_ts, end_ts]
                        }
                    ]
                }
            ],
            "view": "table"
        }

        # Add cloud provider filter if specified
        # Note: The user example didn't explicitly show where cloud_provider goes in the new structure
        # but based on previous code it was a top level field or part of match. 
        # However, the user request specifically asked to match the provided JSON structure.
        # If cloud_provider is needed, it might need to be added to 'match' or 'conditions'.
        # For now, I will assume the previous logic of adding it to the payload is still valid 
        # OR it should be added to the conditions. 
        # Let's check the previous implementation: payload["cloud_type"] = [cloud_provider]
        # The new structure is very different. 
        # I will add it as a top-level field as before, but I should be careful.
        # Actually, looking at the user example, it seems strictly about the filter structure.
        # I will keep the cloud_type if it was there, but the user example shows a specific structure.
        # Let's try to add it to 'match' if provided, or keep it top level if that was the pattern.
        # The previous code had: payload["cloud_type"] = [cloud_provider]
        # I will preserve that behavior but merge it with the new structure.
        
        if cloud_provider:
            if cloud_provider.lower() == "aws":
                 payload["cloud_type"] = ["aws_sagemaker", "aws_bedrock"]
            else:
                 payload["cloud_type"] = [cloud_provider]

        async with httpx.AsyncClient() as client:
            response = await client.post(
                endpoint,
                headers=self.headers,
                json=payload,
                timeout=30.0
            )
            response.raise_for_status()
            return response.json()

