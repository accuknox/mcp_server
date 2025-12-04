import logging
import os
from typing import Any, Dict, Literal, Optional

import httpx
from httpx import ConnectTimeout, HTTPStatusError, ReadTimeout

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
    base_url_override: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
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
        base_url_override: Optional base URL to use instead of the configured one.
        headers: Optional headers to use instead of the default ones.

    Returns:
        Parsed JSON response as a dictionary.
    """
    if base_url_override:
        base_url = base_url_override.rstrip("/")
    else:
        base_url = BASE_URLS.get(base_url_type)

    if not base_url:
        raise ValueError(f"Base URL for '{base_url_type}' is not configured.")

    url = f"{base_url}/{endpoint.lstrip('/')}"
    logger.info(f"API endpoint {url}, {params}, {data}")

    request_headers = headers if headers is not None else HEADERS

    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            if method.upper() == "GET":
                response = await client.get(url, headers=request_headers, params=params)
            elif method.upper() == "POST":
                response = await client.post(
                    url,
                    headers=request_headers,
                    json=data,
                    params=params,
                )
            else:
                return {"error": f"Unsupported method '{method}'"}

            response.raise_for_status()
            return response.json()

        except ReadTimeout:
            logger.error(f"Request to {url} timed out after {timeout}s")
            return {"error": "Request timed out. The API took too long to respond."}

        except ConnectTimeout:
            logger.error(f"Connection to {url} timed out")
            return {"error": "Connection timed out. Unable to reach the API server."}

        except HTTPStatusError as e:
            logger.error(
                f"API returned HTTP {e.response.status_code}: {e.response.text}",
            )
            return {
                "error": f"API error {e.response.status_code}",
                "details": e.response.text,
            }

        except Exception as e:
            logger.exception(f"Unexpected API error: {e}")
            return {"error": "Unexpected API error occurred"}
