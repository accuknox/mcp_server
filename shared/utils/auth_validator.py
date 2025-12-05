import base64
import os
import time
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse

import httpx
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from fastmcp import Context
from jose import JOSEError, jwt

from logging_config import logger


class CustomJWTVerifier:
    JWKS_TTL_SECONDS = 3600

    def __init__(self):
        self.issuer_cache: Dict[str, Dict[str, any]] = {}

    def _b64_to_int(self, b64: str) -> int:
        padding = "=" * ((4 - len(b64) % 4) % 4)
        decoded = base64.urlsafe_b64decode(b64 + padding)
        return int.from_bytes(decoded, "big")

    def _build_pubkey(self, n_b64: str, e_b64: str = "AQAB"):
        n = self._b64_to_int(n_b64)
        e = self._b64_to_int(e_b64)
        numbers = rsa.RSAPublicNumbers(e, n)
        return numbers.public_key(default_backend())

    async def _fetch_jwks(self, base_url: str):
        url = f"{base_url}/api/v1/jwks/"
        async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()

        jwk = data["keys"][0]
        public_key = self._build_pubkey(jwk["n"], jwk.get("e", "AQAB"))
        self.issuer_cache[base_url] = {
            "public_key": public_key,
            "expires_at": time.time() + self.JWKS_TTL_SECONDS,
        }

    async def _get_public_key(self, base_url: str):
        cached = self.issuer_cache.get(base_url)
        if not cached or cached["expires_at"] < time.time():
            await self._fetch_jwks(base_url)
        return self.issuer_cache[base_url]["public_key"]

    async def verify(self, base_url: str, token: str) -> Tuple[bool, str]:
        try:
            hostname = urlparse(base_url).hostname
            if not hostname:
                return False, "invalid_base_url"

            unverified = jwt.get_unverified_claims(token)
            token_iss = unverified.get("iss")
            if token_iss != hostname:
                return False, "issuer_mismatch"

            public_key = await self._get_public_key(base_url)

            claims = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                issuer=hostname,
                options={"verify_aud": False},
            )

            exp = claims.get("exp")
            if exp and exp < time.time():
                return False, "expired"

            return True, ""
        except JOSEError:
            return False, "invalid_signature"
        except Exception as e:
            logger.error(f"Token validation failed unexpectedly: {str(e)}")
            return False, "error"


def _get_auth_context(ctx: Context) -> tuple[Optional[str], Optional[str]]:
    """Helper to extract auth context from request"""

    default_base_url = os.getenv("ACCUKNOX_CSPM_BASE_URL")
    default_token = os.getenv("ACCUKNOX_API_TOKEN")

    try:
        if not ctx:
            logger.warning("No context provided")
            return default_base_url, default_token

        req = ctx.get_http_request()
        if not req:
            logger.warning("No HTTP request found")
            return default_base_url, default_token

        headers = req.headers or {}
        token = headers.get("Token") or default_token
        base_url = (
            headers.get("base_url")
            or req.query_params.get("base_url")
            or default_base_url
        )
        return base_url, token

    except Exception as e:
        logger.error(f"Failed to extract auth context: {e}")
        return default_base_url, default_token
