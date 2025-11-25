#!/usr/bin/env python3
"""
AccuKnox API Direct Test Script
Test different parameter combinations for search_assets API
"""

import asyncio
import os
from typing import Optional

import httpx
from dotenv import load_dotenv

load_dotenv()

# Load from environment
BASE_URL = os.getenv("ACCUKNOX_BASE_URL", "").rstrip("/")
API_TOKEN = os.getenv("ACCUKNOX_API_TOKEN", "")


async def test_search_assets(
    asset_id: Optional[str] = None,
    type_name: Optional[str] = None,
    type_category: Optional[str] = None,
    label_name: Optional[str] = None,
    region: Optional[str] = None,
    cloud_provider: Optional[str] = None,
    page: int = 1,
    page_size: int = 100,
):
    """
    Test AccuKnox search_assets API with different parameters
    """

    endpoint = f"{BASE_URL}/api/v1/assets"

    headers = {
        "Authorization": f"Bearer {API_TOKEN}",
        "Content-Type": "application/json",
    }

    # Build query parameters
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

    print("\n" + "=" * 70)
    print("TESTING ACCUKNOX API")
    print("=" * 70)
    print(f"Endpoint: {endpoint}")
    print(f"Parameters: {params}")
    print(f"Headers: Authorization Bearer {'***' if API_TOKEN else 'MISSING'}")
    print("=" * 70 + "\n")

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                endpoint,
                headers=headers,
                params=params,
                timeout=30.0,
            )

            print(f"✅ Status Code: {response.status_code}")
            print(f"✅ Response Headers: {dict(response.headers)}")
            print("\n" + "=" * 70)
            print("RESPONSE DATA")
            print("=" * 70)

            if response.status_code == 200:
                data = response.json()
                print(f"Response JSON: {data}")

                # Show summary if results exist
                if isinstance(data, dict):
                    if "results" in data:
                        print(f"\n✅ Total results: {len(data.get('results', []))}")
                        print(f"✅ Count: {data.get('count', 'N/A')}")
                    elif "data" in data:
                        print(f"\n✅ Data keys: {list(data.keys())}")
            else:
                print(f"❌ Error Response: {response.text}")

            print("=" * 70 + "\n")
            return response

    except httpx.HTTPStatusError as e:
        print(f"❌ HTTP Error: {e}")
        print(f"Response: {e.response.text if hasattr(e, 'response') else 'N/A'}")
    except httpx.ConnectError as e:
        print(f"❌ Connection Error: {e}")
        print("Check if BASE_URL is correct")
    except Exception as e:
        print(f"❌ Error: {type(e).__name__}: {e}")


async def test_model_stats():
    """
    Test AccuKnox model-stats API
    """
    endpoint = f"{BASE_URL}/api/v1/modelknox/dashboard/model-stats/"

    headers = {
        "Authorization": f"Bearer {API_TOKEN}",
        "Content-Type": "application/json",
    }

    params = {"last_seen_after": "1762506552", "last_seen_before": "1763716152"}

    print("\n" + "=" * 70)
    print("TESTING MODEL STATS API")
    print("=" * 70)
    print(f"Endpoint: {endpoint}")
    print(f"Parameters: {params}")
    print("=" * 70 + "\n")

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                endpoint,
                headers=headers,
                params=params,
                timeout=30.0,
            )

            print(f"✅ Status Code: {response.status_code}")

            if response.status_code == 200:
                data = response.json()
                print(f"Response JSON: {data}")
            else:
                print(f"❌ Error Response: {response.text}")

            print("=" * 70 + "\n")
            return response

    except Exception as e:
        print(f"❌ Error: {type(e).__name__}: {e}")


async def main():
    """
    Run different test cases
    Modify the parameters below to test different scenarios
    """

    # Check configuration first
    print("\n" + "=" * 70)
    print("CONFIGURATION CHECK")
    print("=" * 70)
    print(f"BASE_URL: {BASE_URL if BASE_URL else '❌ MISSING'}")
    print(
        f"API_TOKEN: {'✅ Present (' + str(len(API_TOKEN)) + ' chars)' if API_TOKEN else '❌ MISSING'}",
    )
    print("=" * 70)

    if not BASE_URL or not API_TOKEN:
        print("\n❌ Error: Missing BASE_URL or API_TOKEN in .env file")
        return

    # ===================================================================
    # TEST CASES - MODIFY THESE TO TEST DIFFERENT PARAMETER COMBINATIONS
    # ===================================================================

    print("\n\n🧪 TEST 1: Basic call with no filters")
    await test_search_assets(page=1, page_size=10)

    print("\n\n🧪 TEST 2: Filter by type_name")
    await test_search_assets(type_name="EC2", page_size=10)

    print("\n\n🧪 TEST 3: Filter by region")
    await test_search_assets(region="us-east-1", page_size=10)

    print("\n\n🧪 TEST 4: Filter by cloud_provider and type_category")
    await test_search_assets(
        cloud_provider="AWS",
        type_category="Compute",
        page_size=10,
    )

    print("\n\n🧪 TEST 5: Multiple filters combined")
    await test_search_assets(
        cloud_provider="AWS",
        region="us-west-2",
        type_name="S3",
        page_size=5,
    )

    print("\n\n🧪 TEST 6: label filters combined")
    await test_search_assets(label_name="K8SJOB")

    print("\n\n🧪 TEST 7: Model Stats API")
    await test_model_stats()

    # ===================================================================
    # ADD YOUR OWN TEST CASES BELOW
    # ===================================================================

    # print("\n\n🧪 TEST 6: Your custom test")
    # await test_search_assets(
    #     asset_id="your-asset-id",
    #     page_size=10
    # )


if __name__ == "__main__":
    asyncio.run(main())
