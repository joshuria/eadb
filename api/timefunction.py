# -*- coding: utf-8 -*-
"""Defines date time related functions.
We cannot define constants in common.py, since it causes circular import.
"""
from datetime import datetime, timezone


def epochMSToDateTime(epoch: int) -> datetime:
    """Convert unix epoch (ms) to datetime instance."""
    return epochToDateTime(epoch * .001)

def epochToDateTime(epoch: float) -> datetime:
    """Convert unix epoch (second) to datetime instance."""
    return datetime.fromtimestamp(epoch, timezone.utc)

def dateTimeToEpochMS(dt: datetime) -> int:
    """Convert datetime instance to unix epoch (ms)."""
    return dateTimeToEpoch(dt) * 1000

def dateTimeToEpoch(dt: datetime) -> float:
    """Convert datetime instance to unix epoch (ms)."""
    return dt.replace(tzinfo=timezone.utc).timestamp() if dt.tzinfo is None else dt.timestamp()

def nowUnixEpochMS() -> int:
    """Get current unix epoch (ms)."""
    return nowUnixEpoch() * 1000

def nowUnixEpoch() -> float:
    """Get current unix epoch (second)."""
    return now().timestamp()

def now() -> datetime:
    """Get UTC current datetime instance."""
    return datetime.now(timezone.utc)

ZeroDateTime = epochToDateTime(0)
