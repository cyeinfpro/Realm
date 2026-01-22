import os
from fastapi import Header, HTTPException, status


def get_api_key() -> str:
    return os.environ.get("AGENT_API_KEY", "")


def require_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    key = get_api_key()
    if key and x_api_key != key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="API Key 无效")
