# -*- coding: utf-8 -*-
"""JWT manager for stateless auth user state."""
from flask_jwt_extended import JWTManager
from flask_jwt_extended.utils import create_access_token, get_jwt_identity
from ..common import constructErrorResponse
from ..config import GlobalConfig


class JwtManager:
    """Singleton JWT manager."""
    jwt = JWTManager()

    @staticmethod
    def initialize(app) -> None:
        """Initialize manager with flask app intance."""
        JwtManager.jwt.init_app(app)

        @JwtManager.jwt.expired_token_loader
        def expiredTokenHandler():
            return constructErrorResponse(
                401, 10,
                'JWT expired' if GlobalConfig.ServerDebug else '')

        @JwtManager.jwt.invalid_token_loader
        def invalidTokenHandler(msg):
            return constructErrorResponse(
                401, 11,
                ('JWT is invalid: %s' % msg) if GlobalConfig.ServerDebug else '')

        @JwtManager.jwt.unauthorized_loader
        def missingJWTHandler(msg):
            return constructErrorResponse(
                401, 12,
                ('JWT is missing: %s' % msg) if GlobalConfig.ServerDebug else '')

        @JwtManager.jwt.user_lookup_error_loader
        def invalidUserErrorhandler(_, payload):
            return constructErrorResponse(
                401, 13,
                ('JWT user is invalid: %s' % payload) if GlobalConfig.ServerDebug else '')

    @staticmethod
    def generateToken(identity: str) -> str:
        """Generate JWT token by given user Id."""
        return create_access_token(identity=identity)

    @staticmethod
    def getCurrentUserId() -> str:
        """Get current user's Id which is stored in JWT."""
        return get_jwt_identity()
