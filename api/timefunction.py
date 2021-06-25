# -*- coding: utf-8 -*-
"""Defines date time related functions.
We cannot define constants in common.py, since it causes circular import.
"""
from datetime import datetime, timezone, timedelta


def epochMSToDateTime(epoch: int) -> datetime:
    """Convert unix epoch (ms) to datetime instance."""
    return epochToDateTime(epoch * .001)

def epochToDateTime(epoch: float) -> datetime:
    """Convert unix epoch (second) to datetime instance."""
    return datetime.fromtimestamp(epoch, timezone.utc)

def dateTimeToEpochMS(dt: datetime) -> int:
    """Convert datetime instance to unix epoch (ms)."""
    return int(dateTimeToEpoch(dt) * 1000)

def dateTimeToEpoch(dt: datetime) -> float:
    """Convert datetime instance to unix epoch (ms)."""
    return dt.replace(tzinfo=timezone.utc).timestamp() \
        if dt.tzinfo is None else dt.astimezone(timezone.utc).timestamp()

def toUTCDateTime(dt: datetime) -> datetime:
    """Convert to UTC timezone."""
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt

def nowUnixEpochMS() -> int:
    """Get current unix epoch (ms)."""
    return int(nowUnixEpoch() * 1000)

def nowUnixEpoch() -> float:
    """Get current unix epoch (second)."""
    return datetime.now().timestamp()
    #return now().timestamp()

def now() -> datetime:
    """Get UTC current datetime instance."""
    return datetime.now(timezone.utc)

def addDay(dt: datetime, days: int) -> datetime:
    """Add specified days to datetime."""
    return dt + timedelta(days=days)

ZeroDateTime = epochToDateTime(0)
# Magic number 4102488000 means 2100-01-01 12-00-00 in UTC
InfDateTime = epochToDateTime(4102488000)

def isZeroDateTime(dt: datetime) -> bool:
    """Identify if given datetime is ZeroDateTime.
     :note: this method uses hard-coded year 1980 as identification standard.
    """
    return dt.year < 1980
