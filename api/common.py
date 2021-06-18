# -*- coding: utf-8 -*-
""" Common validator and utility functions. """
from typing import Tuple
from .model import ErrorCode
from .config import GlobalConfig


def verifyHeader(headers) -> Tuple[bool, str, int]:
    """Verify request headers.
    Note that the "Authorization" header is checked by JWT.
    Common headers:
      - x-access-apikey      The API key.
      - x-access-name        Client app name.
      - x-access-version     Client app version.
      - User-Agent
     :param headers: request dict-like headers.
     :return: verify success or fail with extra message.
    """
    if 'x-access-apikey' not in headers:
        return (False, "Missing header: x-access-apikey.", ErrorCode.MissingHeader) \
            if GlobalConfig.ServerDebug \
            else (False, "", ErrorCode.MissingHeader)
    if ('x-access-name' not in headers) or ('x-access-version' not in headers):
        return \
            (False, "Missing header: x-access-name or x-access-version.", ErrorCode.MissingHeader) \
            if GlobalConfig.ServerDebug \
            else (False, "", ErrorCode.MissingHeader)

    if 'User-Agent' not in headers:
        return (False, "Missing header: User-Agent.", ErrorCode.MissingHeader) \
            if GlobalConfig.ServerDebug \
            else (False, "", ErrorCode.MissingHeader)
    if (GlobalConfig.AppUserAgent != '') and (headers['User-Agent'] != GlobalConfig.AppUserAgent):
        return (False, "Invalid User-Agent", ErrorCode.InvalidUserAgent) \
            if GlobalConfig.ServerDebug \
            else  (False, "", ErrorCode.InvalidUserAgent)
    return True, "", ErrorCode.NoError
