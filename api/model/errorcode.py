# -*- coding: utf-8 -*-
"""This file defines all supported detail error code."""

class ErrorCode:
    """Detail response code."""
    NoError = 0
    # Headers
    # Missing headers: x-access-apikey, x-access-name, User-Agent
    MissingHeader = 0x100
    # Wrong User-Agent
    InvalidUserAgent = 0x101

    # Parameters
    # Missing parameter
    MissingParameter = 0x200
    # Invalid parameter format
    InvalidParameter = 0x201
    # User not exist
    UserNotExist = 0x202
    # User already exist (when creating)
    UserAlreadyExist = 0x203

    # Auth
    # Admin only
    AuthAdminOnly = 0x300
    AuthUserNotMatch = 0x301
    AuthUserDisabled = 0x302

    # Activate
    LicenseNotExist = 0x400
    LicenseConsumedButActivateFail = 0x401
