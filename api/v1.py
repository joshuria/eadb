# -*- coding: utf-8 -*-
"""Defines all information querying methods."""
from flask import Blueprint, jsonify, make_response, request
from flask_jwt_extended import create_access_token
from flask_jwt_extended.utils import get_jwt_identity
from flask_jwt_extended.view_decorators import jwt_required
from common import verifyHeader
from config import GlobalConfig
from database import getUser, constructErrorResponse

V1Api = Blueprint('V1Api', __name__)


@V1Api.route('auth', methods=['POST'])
def auth():
    """Do JWT auth."""
    result, msg = verifyHeader(request.headers)
    if not result:
        return constructErrorResponse(400, 1, msg)
    userId = request.json.get('userId', None)
    password = request.json.get('password', None)
    if (userId is None) or (password is None):
        return constructErrorResponse(
            400, 2, 'Missing userId or password' if GlobalConfig.ServerDebug else '')
    user = getUser(userId, password)
    if user is None:
        return constructErrorResponse(
            404, 3, 'Invalid userId or password' if GlobalConfig.ServerDebug else '')
    # Success
    response = make_response(jsonify(), 200)
    response.headers['JWT'] = create_access_token(identity=userId)
    return response

@V1Api.route('user/<userId>', methods=['GET'])
@jwt_required()
def queryUser(userId):
    """Query given user's all available products state."""
    result, msg = verifyHeader(request.headers)
    if not result:
        return constructErrorResponse(400, 1, msg)
    if userId is None:
        return constructErrorResponse(
            400, 2, 'Missing userId' if GlobalConfig.ServerDebug else '')
    # Check JWT with userId (403)
    jwtUserId = get_jwt_identity()
    if jwtUserId != userId:
        return constructErrorResponse(
            403, 11, 'Invalid JWT' if GlobalConfig.ServerDebug else '')
    # Check userId exist
    user = getUser(userId)
    if user is None:
        return constructErrorResponse(
            404, 3, 'User not exist.' if GlobalConfig.ServerDebug else '')
    return make_response(jsonify(user), 200)
