import logging
import os
from typing import Any, Dict, Literal, Optional

import httpx

# Create a module-level logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
# Optional: add a console handler if not already configured
if not logger.hasHandlers():
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    ch.setFormatter(formatter)
    logger.addHandler(ch)

BASE_URLS = {
    "cwpp": os.getenv("ACCUKNOX_CWPP_BASE_URL", "").rstrip("/"),
    "cspm": os.getenv("ACCUKNOX_CSPM_BASE_URL", "").rstrip("/"),
}

api_token = os.getenv("ACCUKNOX_API_TOKEN", "")
HEADERS = {
    "Authorization": f"Bearer {api_token}",
    "Content-Type": "application/json",
}


async def call_api(
    endpoint: str,
    base_url_type: Literal["cwpp", "cspm"] = "cspm",
    method: str = "GET",
    params: Optional[Dict[str, Any]] = None,
    data: Optional[Dict[str, Any]] = None,
    timeout: float = 30.0,
) -> dict:
    """
    Utility function to call GET or POST APIs.

    Args:
        endpoint: The API path after the base URL.
        base_url_type: Either "cwpp" or "cspm" to select the base URL (default: "cspm").
        method: "GET" or "POST".
        params: Optional query parameters for GET requests.
        data: Optional JSON body for POST requests.
        timeout: Request timeout in seconds.

    Returns:
        Parsed JSON response as a dictionary.
    """
    base_url = BASE_URLS.get(base_url_type)
    if not base_url:
        raise ValueError(f"Base URL for '{base_url_type}' is not configured.")

    url = f"{base_url}/{endpoint.lstrip('/')}"
    logger.info(f"API endpoint {url}, {params}, {data}")

    async with httpx.AsyncClient() as client:
        if method.upper() == "GET":
            response = await client.get(
                url,
                headers=HEADERS,
                params=params,
                timeout=timeout,
            )
        elif method.upper() == "POST":
            response = await client.post(
                url,
                headers=HEADERS,
                json=data,
                params=params,
                timeout=timeout,
            )
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")

        response.raise_for_status()
        api_data = response.json()
        # logger.info(f"API endpoint {api_data}")
        return api_data
