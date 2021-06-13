# -*- coding: utf-8 -*-
"""Defines all information querying methods."""
from typing import Tuple
from flask import Blueprint, jsonify, make_response, request
from flask_jwt_extended import create_access_token
from flask_jwt_extended.utils import get_jwt_identity
from flask_jwt_extended.view_decorators import jwt_required
import mongoengine as me
from mongoengine.errors import DoesNotExist
from common import verifyHeader
from config import GlobalConfig
from database import constructErrorResponse
from model import Log, LogOperation, Status, User

V1Api = Blueprint('V1Api', __name__)


def _generalVerify(
    userId: str, verifyUserIdFormat: bool=True, verifyJWT: bool=True, needGetUser: bool=True
) -> Tuple[bool, str, User, me.QuerySet]:
    """Do common verification flow. Include:
     - Headers (400)
     - JWT info verify (403)
     - User id exists or not (404)
     :note: this method is not suitable for `/auth`.
     :return: tuple of:
          - verify success or fail.
          - verify fail response
          - User instance if verify success and `needGetUser` is True.
          - Query set instance if success.
    """
    # Verify header (400)
    result, msg = verifyHeader(request.headers)
    if not result:
        return False, constructErrorResponse(400, 1, msg), None, None
    if userId is None:
        return (
            False,
            constructErrorResponse(400, 2, 'Missing userId' if GlobalConfig.ServerDebug else ''),
            None, None)
    # Verify userId's format (400)
    if verifyUserIdFormat:
        # TODO
        pass
    # Check JWT with userId (403)
    if verifyJWT:
        jwtUserId = get_jwt_identity()
        if jwtUserId != userId:
            return (
                False, constructErrorResponse(
                    403, 11, 'Invalid JWT' if GlobalConfig.ServerDebug else ''),
                None, None)
    # Check userId exist
    query = User.getById(userId, 0)
    if needGetUser:
        try:
            user = query.get()
        except DoesNotExist:
            return (
                False,
                constructErrorResponse(
                    404, 3, 'User not exist' if GlobalConfig.ServerDebug else ''),
                None, None)
    else:
        user = None
    # Check user is enabled (403)
    # TODO
    return True, '', user, query

@V1Api.route('auth', defaults={'detail': 0}, methods=['POST'])
@V1Api.route('auth/<int:detail>', methods=['POST'])
def auth(detail: int = 0):
    """Do JWT auth and (optionally) get user detail info.
    If detail is set to 1, the following info will be returned:
      - createTime
      - status
      - lastLoginTime
      - lastLoginIp
      - eaStatus
      - log
    POST parameters:
      - userId: user's ID.
      - password: user's hashed password.
    """
    # Verify header
    result, msg = verifyHeader(request.headers)
    if not result:
        return constructErrorResponse(400, 1, msg)
    userId = request.json.get('userId', None)
    password = request.json.get('password', None)
    if (userId is None) or (password is None):
        return constructErrorResponse(
            400, 2, 'Missing userId or password' if GlobalConfig.ServerDebug else '')
    # Get user
    query = User.getById(userId, excludePassword=False, excludeFieldsForAuth=True)
    try:
        user = query.get()
    except DoesNotExist:
        user = None
    if (user is None) or (user.password != password):
        return constructErrorResponse(
            404, 3, 'Invalid userId or password' if GlobalConfig.ServerDebug else '')
    if user.status == Status.Disabled:
        return constructErrorResponse(
            403, 3, 'User is disabled' if GlobalConfig.ServerDebug else '')
    # Success
    user.password = None
    response = make_response(jsonify(user) if detail == 1 else jsonify(), 200)
    response.headers['JWT'] = create_access_token(identity=userId)
    return response

@V1Api.route('user/<userId>', methods=['GET'])
@jwt_required()
def queryUser(userId: str):
    """Query given user's all available products state.
     :param userId: user's id. (url escaped)
     :note: this method will NOT verify userId's format.
    """
    success, errorResponse, user, _ = _generalVerify(userId, False)
    return make_response(jsonify(user), 200) if success else errorResponse

@V1Api.route('user/<userId>', methods=['POST'])
@jwt_required()
def createUser(userId: str):
    """Create a new user.
     :param userId: user's id. (url escaped)
    POST parameters:
      - password: user's hashed password.
      - status: (optional) user's default status. Default is 1 (enabled).
    """
    success, errorResponse, _, _ = _generalVerify(userId, True, False, False)
    if not success:
        return errorResponse
    # Verify other fields
    password = request.json.get('password', None)
    if password is None:
        return constructErrorResponse(
            400, 2, 'Missing password' if GlobalConfig.ServerDebug else '')
    # Insert new user
    user = User(
        uid=userId,
        password=password,
        status=request.json.get('status', Status.Enabled),
        log=[Log(operation=LogOperation.CreateUser, ip=request.remote_addr)])
    try:
        user.save(force_insert=True)
    except me.errors.NotUniqueError:
        return constructErrorResponse(
            409, 2, 'User alreay exists' if GlobalConfig.ServerDebug else '')
    return make_response(jsonify({}), 200)
