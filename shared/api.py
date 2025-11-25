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
