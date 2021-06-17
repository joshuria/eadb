# -*- coding: utf-8 -*-
"""Defines all information querying methods."""
from typing import Tuple
from flask import Blueprint, jsonify, make_response, request
from flask_jwt_extended import create_access_token
from flask_jwt_extended.utils import get_jwt_identity
from flask_jwt_extended.view_decorators import jwt_required
import mongoengine as me
from mongoengine.errors import DoesNotExist
from .common import verifyHeader
from .config import GlobalConfig
from .database import constructErrorResponse
from .model import Log, LogOperation, Status, User

V1Api = Blueprint('V1Api', __name__)


def _generalVerify(
    userId: str, verifyUserIdFormat: bool=True, verifyJWT: bool=True, adminOnly: bool=False
) -> Tuple[bool, str]:
    """Do common verification flow. Include:
     - Headers (400)
     - JWT info verify (403)
     - User id exists or not (404)
     :note: this method is not suitable for `/auth`.
     :return: tuple of:
          - verify success or fail.
          - verify fail response
    """
    # Verify header (400)
    result, msg = verifyHeader(request.headers)
    if not result:
        return False, constructErrorResponse(400, 1, msg)
    if userId is None:
        return (
            False,
            constructErrorResponse(400, 2, 'Missing userId' if GlobalConfig.ServerDebug else ''))
    # Verify userId's format (400)
    if verifyUserIdFormat and (not User.verifyUserId(userId)):
        return (
            False,
            constructErrorResponse(
                400, 3, 'Invalid user id format' if GlobalConfig.ServerDebug else ''))
    # Check JWT with userId (403)
    if verifyJWT:
        # Verify if is admin only
        activeUser = get_jwt_identity()
        if adminOnly and (activeUser != GlobalConfig.DbDefaultAdmin):
            return False, constructErrorResponse(
                403, 3, 'JWT active user is not admin' if GlobalConfig.ServerDebug else '')
        if (not adminOnly) and (activeUser not in (GlobalConfig.DbDefaultAdmin, userId)):
            return False, constructErrorResponse(
                403, 3, 'JWT active user is not current user' if GlobalConfig.ServerDebug else '')
    return True, ''

@V1Api.route('auth', defaults={'login': 0}, methods=['POST'])
@V1Api.route('auth/<int:login>', methods=['POST'])
def auth(login: int = 0):
    """Do JWT auth and (optionally) get user detail info.
    If login is set to 1, the following info will be returned:
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
    userId = request.json.get('userId', None)
    password = request.json.get('password', None)
    if (userId is None) or (password is None):
        return constructErrorResponse(
            400, 2, 'Missing userId or password' if GlobalConfig.ServerDebug else '')
    # Verify header
    success, errorResponse = _generalVerify(userId, False, False)
    if not success:
        return errorResponse
    # Get user
    query = User.getById(
        userId, excludeList=[] if login == 1 else ['uid', 'availableLicenses', 'auth', 'log'])
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
    # TODO: optional: write login log if detail = 1
    user.password = None
    response = make_response(jsonify(user) if login == 1 else jsonify(), 200)
    response.headers['JWT'] = create_access_token(identity=userId)
    return response

@V1Api.route('user/<userId>', methods=['GET'])
@jwt_required()
def queryUser(userId: str):
    """Query given user's all available products state.
     :param userId: user's id. (url escaped)
     :note: this method will NOT verify userId's format.
    """
    success, errorResponse = _generalVerify(userId)
    if not success:
        return errorResponse
    query = User.getById(userId, excludeList=('password', 'auth'))
    try:
        user = query.get()
    except DoesNotExist:
        user = None
    if user is None:
        return constructErrorResponse(
            404, 3, 'Invalid userId or password' if GlobalConfig.ServerDebug else '')
    if user.status == Status.Disabled:
        return constructErrorResponse(
            403, 3, 'User is disabled' if GlobalConfig.ServerDebug else '')
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
    success, errorResponse = _generalVerify(userId, adminOnly=True)
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

@V1Api.route('user/<userId>', methods=['PUT'])
@jwt_required()
def modifyUser(userId: str):
    """Modify user's data."""
    success, errorResponse = _generalVerify(userId)
    if not success:
        return errorResponse
    # Update data
    conditions = {}
    for c in ('password', 'status'):
        value = request.json.get(c, None)
        if value is not None:
            conditions[c] = value
    try:
        User.getById(userId).update_one(**conditions)
    except DoesNotExist:
        return constructErrorResponse(
            404, 3, 'UserId not exist' if GlobalConfig.ServerDebug else '')
    # TODO: write modify log
    return make_response(jsonify({}), 200)

@V1Api.route('user/<userId>', methods=['DELETE'])
@jwt_required()
def deleteUser(userId: str):
    """Remove a user."""
    success, errorResponse = _generalVerify(userId, adminOnly=True)
    if not success:
        return errorResponse
    # Update data
    try:
        User.getById(userId).delete()
    except DoesNotExist:
        return constructErrorResponse(
            404, 3, 'UserId not exist' if GlobalConfig.ServerDebug else '')
    # TODO: write delete log
    return make_response(jsonify({}), 200)

@V1Api.route('user-log/<userId>', methods=['GET'])
@jwt_required()
def getUserLog(userId: str):
    """Get user's operation logs."""
    raise NotImplementedError

@V1Api.route('license/<userId>', methods=['POST'])
@jwt_required()
def buyLicense(userId: str):
    """Buy license for specified user."""
    raise NotImplementedError

@V1Api.route('license/<userId>', methods=['GET'])
@jwt_required()
def getLicense(userId: str):
    """Get user's all available (not activated) licenses."""
    raise NotImplementedError

@V1Api.route('query-license', methods=['POST'])
@jwt_required()
def queryLicenseStatus():
    """Query a list of licenses status."""
    raise NotImplementedError

@V1Api.route('activate/<userId>', methods=['POST'])
@jwt_required()
def activateLicense(userId: str):
    """Activate a list of licenses."""
    raise NotImplementedError
