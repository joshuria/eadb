# -*- coding: utf-8 -*-
"""JWT manager maintenance file."""
from flask_jwt_extended import JWTManager
from .database import constructErrorResponse
from .config import GlobalConfig

jwt = JWTManager()

def initializeJwt(app) -> None:
    """Initialize JWT manager instance."""
    jwt.init_app(app)

    @jwt.expired_token_loader
    def expiredTokenHandler():
        return constructErrorResponse(
            401, 10,
            'JWT expired' if GlobalConfig.ServerDebug else '')

    @jwt.invalid_token_loader
    def invalidTokenHandler(msg):
        return constructErrorResponse(
            401, 11,
            ('JWT is invalid: %s' % msg) if GlobalConfig.ServerDebug else '')

    @jwt.unauthorized_loader
    def missingJWTHandler(msg):
        return constructErrorResponse(
            401, 12,
            ('JWT is missing: %s' % msg) if GlobalConfig.ServerDebug else '')

    @jwt.user_lookup_error_loader
    def invalidUserErrorhandler(_, payload):
        return constructErrorResponse(
            401, 13,
            ('JWT user is invalid: %s' % payload) if GlobalConfig.ServerDebug else '')
