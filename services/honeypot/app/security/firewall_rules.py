"""
In-Memory Dynamic Firewall
Blacklists IPs that have triggered extreme behavioral score (10.0) or severe limits.
"""
import asyncio

_blocked_ips: set[str] = set()
_lock = asyncio.Lock()

async def is_ip_blocked(ip: str) -> bool:
    """Check if the IP is dynamically firewalled."""
    async with _lock:
        return ip in _blocked_ips

async def block_ip(ip: str) -> None:
    """Add IP to the dynamic firewall blacklist."""
    async with _lock:
        _blocked_ips.add(ip)
