import os
from typing import Any, Dict, Literal, Optional

import httpx
from httpx import ConnectTimeout, HTTPStatusError, ReadTimeout

from logging_config import logger


async def call_api(
    endpoint: str,
    base_url_type: Literal["cwpp", "cspm"] = "cspm",
    method: str = "GET",
    params: Optional[Dict[str, Any]] = None,
    data: Optional[Dict[str, Any]] = None,
    timeout: float = 30.0,
    base_url: Optional[str] = "",
    token: Optional[str] = "",
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
        base_url: Optional base URL to use instead of the configured one.
        api_token: Optional access token to use instead of the default ones.

    Returns:
        Parsed JSON response as a dictionary.
    """
    base_url = base_url.rstrip("/")

    if not base_url:
        raise ValueError(f"Base URL for is not configured.")
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    url = f"{base_url}/{endpoint.lstrip('/')}"
    logger.info(f"API endpoint {url}, {params}, {data}")

    async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
        try:
            if method.upper() == "GET":
                response = await client.get(url, headers=headers, params=params)
            elif method.upper() == "POST":
                response = await client.post(
                    url,
                    headers=headers,
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
