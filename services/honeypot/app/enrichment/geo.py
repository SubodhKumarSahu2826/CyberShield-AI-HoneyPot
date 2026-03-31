import asyncio
import aiohttp
from app.logger import get_logger

logger = get_logger()

# Free rate limit for ip-api without API key: 45 req/minute.
# We will cache the results in memory to avoid hitting limits for repeated IPs
_geo_cache: dict[str, dict] = {}
_geo_cache_max_size = 1000

async def get_geolocation(ip: str) -> dict:
    """
    Fetch geolocation (country, city, asn) for an IP address.
    Fails fast (1s timeout) to prevent blocking the honeypot pipeline.
    """
    if ip in ("127.0.0.1", "localhost", "0.0.0.0", "unknown") or ip.startswith("192.168.") or ip.startswith("10."):
        return {"country": "Local", "city": "Network", "asn": "Private"}

    if ip in _geo_cache:
        return _geo_cache[ip]

    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,city,isp,as"
    
    try:
        # Very short timeout so we don't slow down the capture response.
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=1.0)) as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get("status") == "success":
                        result = {
                            "country": data.get("country", ""),
                            "city": data.get("city", ""),
                            "asn": data.get("as", "") or data.get("isp", "")
                        }
                        # Cache management
                        if len(_geo_cache) > _geo_cache_max_size:
                            # Randomly prune half to prevent memory leaks (naive but fast)
                            keys_to_delete = list(_geo_cache.keys())[:_geo_cache_max_size//2]
                            for k in keys_to_delete:
                                _geo_cache.pop(k, None)
                        
                        _geo_cache[ip] = result
                        return result
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"Geolocation lookup failed for {ip}: {exc}")

    return {"country": "", "city": "", "asn": ""}
