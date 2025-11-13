"""
AccuKnox API Client
Handles all API interactions with AccuKnox CSPM
"""

import os
import httpx
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

class AccuKnoxClient:
    """Client for AccuKnox CSPM API"""
    
    def __init__(self):
        self.base_url = os.getenv("ACCUKNOX_BASE_URL", "").rstrip('/')
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
        page: int = 1,
        page_size: int = 100,
    ) -> dict:
        """Fetch assets from AccuKnox"""
        
        endpoint = f"{self.base_url}/api/v1/assets"
        params = {"page": page, "page_size": page_size}
        
        if asset_id:
            params["id"] = asset_id
        if type_name:
            params["type__name"] = type_name
        if type_category:
            params["type_category"] = type_category
        if label_name:
            params["label__name"] = label_name
        if region:
            params["region"] = region
        if cloud_provider:
            params["cloud_provider"] = cloud_provider
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                endpoint,
                headers=self.headers,
                params=params,
                timeout=30.0
            )
            response.raise_for_status()
            return response.json()
    
    async def fetch_model_vulnerabilities(self) -> dict:
        """Fetch model vulnerability summary"""
        
        endpoint = f"{self.base_url}/api/v1/modelknox/dashboard/ondemand-model-issues-summary/"
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                endpoint,
                headers=self.headers,
                params={"page": 1},
                timeout=30.0
            )
            response.raise_for_status()
            return response.json()
