# -*- coding: utf-8 -*-
""" Common validator and utility functions. """
from datetime import datetime
from typing import Tuple
from .config import GlobalConfig


# Shared constant
# Define unix epoch 0 in millisecond as datetime
DefaultZeroDateTime = datetime.fromtimestamp(0)

def verifyHeader(headers) -> Tuple[bool, str]:
    """Verify request headers.
    Note that the "Authorization" header is checked by JWT.
    Common headers:
      - x-access-apikey      The API key.
      - x-access-name        Client app name.
      - x-access-version     Client app version.
      - User-Agent
      - Authorization
     :param headers: request dict-like headers.
     :return: verify success or fail with extra message.
    """
    if 'x-access-apikey' not in headers:
        return (False, "Missing header: x-access-apikey.") \
            if GlobalConfig.ServerDebug \
            else (False, "")
    if ('x-access-name' not in headers) or ('x-access-version' not in headers):
        return (False, "Missing header: x-access-name or x-access-version.") \
            if GlobalConfig.ServerDebug \
            else (False, "")

    if 'User-Agent' not in headers:
        return (False, "Missing header: User-Agent.") \
            if GlobalConfig.ServerDebug \
            else (False, "")
    if (GlobalConfig.AppUserAgent != '') and (headers['User-Agent'] != GlobalConfig.AppUserAgent):
        return (False, "Invalid User-Agent") \
            if GlobalConfig.ServerDebug \
            else  (False, "")
    return True, ""
