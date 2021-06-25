# -*- coding: utf-8 -*-
""" Common validator and utility functions. """
from typing import Dict, Tuple
from flask import jsonify, make_response
from .config import GlobalConfig
from .model import ErrorCode


def verifyRequiredHeader(headers) -> Tuple[bool, str, int]:
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

def constructErrorResponse(httpCode: int, code: int, msg: str = '') -> str:
    """Construct ErrorResult response string."""
    return make_response(jsonify({ 'code': code, 'msg': msg }), httpCode)

def generalVerify(
    headers: Dict[str, str],
    adminOnly: bool=False, maintenanceOnly: bool=False
) -> Tuple[bool, str]:
    """Do common verification flow. Include:
      - Headers: x-access-apikey, x-access-name, x-access-version, User-Agent (400)
     :param headers: request headers, i.e. `flask.request.headers`.
     :param adminOnly: specify if the access client must be admin role.
     :param maintenanceOnly: specify if the access client must be maintenance role.
     :return: tuple of:
          - verify success or fail.
          - verify fail response
    """
    # Verify header (400)
    result, msg, code = verifyRequiredHeader(headers)
    if not result:
        return False, constructErrorResponse(400, code, msg)
    apiKey = headers['x-access-apikey']
    if adminOnly:
        if apiKey not in (GlobalConfig.ApiAdminKey, GlobalConfig.ApiMaintenanceKey):
            return False, constructErrorResponse(
                403, ErrorCode.AuthAdminOnly,
                'Cannot use admin only API' if GlobalConfig.ServerDebug else '')
    elif maintenanceOnly:
        if apiKey != GlobalConfig.ApiMaintenanceKey:
            return False, constructErrorResponse(
                403, ErrorCode.AuthAdminOnly,
                'Cannot use maintenance only API' if GlobalConfig.ServerDebug else '')
    else:
        if apiKey not in (
            GlobalConfig.ApiAdminKey, GlobalConfig.ApiMaintenanceKey, GlobalConfig.ApiAppKey
        ):
            return False, constructErrorResponse(
                403, ErrorCode.AuthAdminOnly,
                'Cannot use API' if GlobalConfig.ServerDebug else '')
    return True, ''
