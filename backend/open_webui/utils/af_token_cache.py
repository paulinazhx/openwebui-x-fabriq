"""
Agentic Fabriq token cache utility.
Caches AF tokens with 1-hour expiration per user.
"""

import base64
import json
import logging
import os
import time
from typing import Optional, Dict
from threading import Lock

log = logging.getLogger(__name__)

# ===========================================
# Agentic Fabriq credentials - EDIT HERE
# ===========================================
AF_APP_ID = os.getenv("AF_APP_ID", "org-32a884f6-bc0c-4892-811c-97f1f4e1fd14_openwebui")
AF_APP_SECRET = os.getenv("AF_APP_SECRET", "rOJAYWKzxSKdfmRtXTifNRqzP21Y6gUV")
# Issuer we present to AF when exchanging tokens (Keycloak issuer)
AF_SUBJECT_ISSUER = os.getenv(
    "AF_SUBJECT_ISSUER",
    "https://stagingauth.agenticfabriq.com/realms/agentic-fabric",
)
AF_GATEWAY_URL = os.getenv("AF_GATEWAY_URL", "https://staging.agenticfabriq.com")
# ===========================================

def _log_jwt_claims(token: str, label: str) -> None:
    """
    Log JWT claims without the signature to avoid leaking secrets.
    """
    try:
        parts = token.split(".")
        if len(parts) < 2:
            log.warning(f"{label}: not a JWT")
            return
        payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        scopes = payload.get("scope") or payload.get("scopes")
        log.info(f"{label} claims: iss={payload.get('iss')}, aud={payload.get('aud')}, sub={payload.get('sub')}, scopes={scopes}")
    except Exception as e:
        log.warning(f"{label}: failed to decode JWT payload: {e}")


async def exchange_okta_token_for_af_token(okta_access_token: str) -> Optional[str]:
    """
    Exchange a Keycloak OIDC access token for an AF app token.
    Uses AF SDK's Keycloak-specific exchange (no subject_issuer required).
    """
    # DEBUG: Print full tokens (REMOVE AFTER DEBUGGING)
    log.warning("=== DEBUG: KEYCLOAK ACCESS TOKEN (REMOVE THIS LOG) ===")
    log.warning(f"{okta_access_token}")
    log.warning("=== END KEYCLOAK TOKEN ===")
    
    _log_jwt_claims(okta_access_token, "Keycloak access token")

    try:
        from af_sdk import exchange_keycloak_for_af_token
    except ImportError:
        log.error("af_sdk.exchange_keycloak_for_af_token not available in this SDK version.")
        return None

    try:
        af_token = await exchange_keycloak_for_af_token(
            keycloak_token=okta_access_token,
            app_id=AF_APP_ID,
            secret_key=AF_APP_SECRET,
            gateway_url=AF_GATEWAY_URL,
        )
        if af_token and af_token.access_token:
            # DEBUG: Print full AF token (REMOVE AFTER DEBUGGING)
            log.warning("=== DEBUG: AF APP TOKEN (REMOVE THIS LOG) ===")
            log.warning(f"{af_token.access_token}")
            log.warning("=== END AF TOKEN ===")
            
            _log_jwt_claims(af_token.access_token, "AF app token")
            return af_token.access_token
        return None
    except Exception as e:
        log.error(f"Keycloak token exchange failed: {e}")
        return None

class AFTokenCache:
    """Simple in-memory cache for AF tokens with TTL."""
    
    def __init__(self):
        self._cache: Dict[str, tuple[str, float]] = {}  # user_id -> (token, expires_at)
        self._lock = Lock()
        self.TTL = 3600  # 1 hour in seconds
    
    def get(self, user_id: str) -> Optional[str]:
        """
        Get cached AF token for a user if it exists and is not expired.
        
        Args:
            user_id: The user ID
            
        Returns:
            str: The AF token if valid, None otherwise
        """
        with self._lock:
            if user_id in self._cache:
                token, expires_at = self._cache[user_id]
                
                # Check if token is still valid
                if time.time() < expires_at:
                    log.debug(f"AF token cache hit for user {user_id}")
                    return token
                else:
                    # Token expired, remove from cache
                    log.debug(f"AF token expired for user {user_id}, removing from cache")
                    del self._cache[user_id]
            
            log.debug(f"AF token cache miss for user {user_id}")
            return None
    
    def set(self, user_id: str, token: str) -> None:
        """
        Store an AF token for a user with 1-hour TTL.
        
        Args:
            user_id: The user ID
            token: The AF token to cache
        """
        with self._lock:
            expires_at = time.time() + self.TTL
            self._cache[user_id] = (token, expires_at)
            log.debug(f"AF token cached for user {user_id}, expires at {expires_at}")
    
    def invalidate(self, user_id: str) -> None:
        """
        Invalidate/remove the cached token for a user.
        
        Args:
            user_id: The user ID
        """
        with self._lock:
            if user_id in self._cache:
                del self._cache[user_id]
                log.debug(f"AF token invalidated for user {user_id}")
    
    def clear(self) -> None:
        """Clear all cached tokens."""
        with self._lock:
            self._cache.clear()
            log.debug("AF token cache cleared")
    
    def cleanup_expired(self) -> None:
        """Remove all expired tokens from cache."""
        with self._lock:
            current_time = time.time()
            expired_users = [
                user_id for user_id, (_, expires_at) in self._cache.items()
                if current_time >= expires_at
            ]
            
            for user_id in expired_users:
                del self._cache[user_id]
            
            if expired_users:
                log.debug(f"Cleaned up {len(expired_users)} expired AF tokens")


# Global cache instance
af_token_cache = AFTokenCache()


