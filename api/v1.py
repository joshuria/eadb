# -*- coding: utf-8 -*-
"""Defines all information querying methods."""
from typing import Tuple
from flask import Blueprint, jsonify, make_response, request
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required
import mongoengine as me
from .common import verifyHeader
from .config import GlobalConfig
from .database import constructErrorResponse
from .model import ErrorCode, Log, LogOperation, Status, User

V1Api = Blueprint('V1Api', __name__)


def _generalVerify(
    userId: str, verifyUserIdFormat: bool=True, verifyJWT: bool=True, adminOnly: bool=False
) -> Tuple[bool, str]:
    """Do common verification flow. Include:
     - Headers: x-access-apikey, x-access-name, x-access-version, User-Agent (400)
     - JWT identify info verify (403)
     - User id format (400)
     :param userId: user's id.
     :param verifyUserIdFormat: verify user's id must be email.
     :param verifyJWT: verify JWT identify is specify userId or admin.
     :param adminOnly: specify if the user must be admin.
     :note: this method is not suitable for `/auth`.
     :return: tuple of:
          - verify success or fail.
          - verify fail response
    """
    # Verify header (400)
    result, msg, code = verifyHeader(request.headers)
    if not result:
        return False, constructErrorResponse(400, code, msg)
    if userId is None:
        return (False, constructErrorResponse(
            400, ErrorCode.MissingParameter,
            'Missing userId' if GlobalConfig.ServerDebug else ''))
    # Verify userId's format (400)
    if verifyUserIdFormat and (not User.verifyUserId(userId)):
        return (False, constructErrorResponse(
                400, ErrorCode.InvalidParameter,
                'Invalid user id format' if GlobalConfig.ServerDebug else ''))
    # Check JWT with userId (403)
    if verifyJWT:
        # Verify if is admin only
        activeUser = get_jwt_identity()
        if adminOnly and (activeUser != GlobalConfig.DbDefaultAdmin):
            return False, constructErrorResponse(
                403, ErrorCode.AuthAdminOnly,
                'JWT active user is not admin' if GlobalConfig.ServerDebug else '')
        if (not adminOnly) and (activeUser not in (GlobalConfig.DbDefaultAdmin, userId)):
            return False, constructErrorResponse(
                403, ErrorCode.AuthUserNotMatch,
                'JWT active user is not current user' if GlobalConfig.ServerDebug else '')
    return True, ''

#@V1Api.route('/auth', defaults={'login': 0}, methods=['POST'])
@V1Api.route('/auth', methods=['POST'])
@V1Api.route('/auth/<int:login>', methods=['POST'])
def auth(login: int=0):
    """Do JWT auth and (optionally) get user detail info.
    URL parameter:
      - login: this auth is also for user login. Basic user info is required.
    Parameters:
      - userId: user's ID, can be email or other format.
      - password: user's hashed password.
    Response Status Code:
      - 200: success.
      - 400: if missing header or missing parameter (userId, password).
      - 403: user is disabled.
      - 404: user not found or wrong password.
    Response Data:
    If login is set to 1, the following info will be returned:
      - createTime
      - status
      - lastLoginTime
      - lastLoginIp
      - eaStatus
      - log
    """
    if request.json is None:
        # When client does not send any payload, request.json will be None
        return constructErrorResponse(
            400, ErrorCode.MissingParameter,
            'Missing userId or password' if GlobalConfig.ServerDebug else '')
    userId = request.json.get('userId', None)
    password = request.json.get('password', None)
    if (userId is None) or (password is None):
        return constructErrorResponse(
            400, ErrorCode.MissingParameter,
            'Missing userId or password' if GlobalConfig.ServerDebug else '')
    # Verify header
    success, errorResponse = _generalVerify(userId, False, False)
    if not success:
        return errorResponse
    # Get user
    query = User.getById(
        userId, excludeList=[] if login == 1 else ['uid', 'availableLicenses', 'auth', 'log'])
    try:
        user = query.get()
    except me.errors.DoesNotExist:
        user = None
    if (user is None) or (user.password != password):
        return constructErrorResponse(
            404, ErrorCode.InvalidParameter,
            'Invalid userId or password' if GlobalConfig.ServerDebug else '')
    if user.status == Status.Disabled:
        return constructErrorResponse(
            403, ErrorCode.AuthUserDisabled,
            'User is disabled' if GlobalConfig.ServerDebug else '')
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
     :param userId: user's id.
     :note: this method will NOT verify userId's format.
    URL parameter:
      - userId: user's id to query. This is limited to use email format.
    Response Status Code:
      - 200: success.
      - 400: if missing header or missing parameter (userId).
      - 401: JWT auth fail.
      - 403: user is disabled, JWT indentity does not match to userId, or user try to get other
        user's data.
      - 404: user not found.
    Response Data:
      - createTime
      - status
      - lastLoginTime
      - lastLoginIp
      - eaStatus
      - log
      - licenses
    """
    success, errorResponse = _generalVerify(userId)
    if not success:
        return errorResponse
    query = User.getById(userId, excludeList=('password', 'auth'))
    try:
        user = query.get()
    except me.errors.DoesNotExist:
        user = None
    if user is None:
        return constructErrorResponse(
            404, ErrorCode.AuthUserNotMatch,
            'Invalid userId or password' if GlobalConfig.ServerDebug else '')
    #if user.status == Status.Disabled:
    #    return constructErrorResponse(
    #        403, ErrorCode.AuthUserDisabled,
    #        'User is disabled' if GlobalConfig.ServerDebug else '')
    return make_response(jsonify(user), 200) if success else errorResponse

@V1Api.route('user/<userId>', methods=['POST'])
@jwt_required()
def createUser(userId: str):
    """Create a new user (by admin only).
     :param userId: user's id.
    URL parameter:
      - userId: user's id to query. This is limited to use email format.
    POST parameters:
      - password: user's hashed password.
      - status: (optional) user's default status. Default is 1 (enabled).
    Response Status Code:
      - 200: success.
      - 400: invalid parameter format, missing header, or missing parameter.
      - 401: JWT auth fail.
      - 403: JWT identify user does not have priviledge.
      - 409: userId already exist.
    """
    success, errorResponse = _generalVerify(userId, adminOnly=True)
    if not success:
        return errorResponse
    # Verify other fields
    password = request.json.get('password', None)
    if password is None:
        return constructErrorResponse(
            400, ErrorCode.MissingParameter,
            'Missing password' if GlobalConfig.ServerDebug else '')
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
            409, ErrorCode.UserAlreadyExist,
            'User alreay exists' if GlobalConfig.ServerDebug else '')
    return make_response(jsonify({}), 200)

@V1Api.route('user/<userId>', methods=['PUT'])
@jwt_required()
def modifyUser(userId: str):
    """Modify user's data.
     :param userId: user's id.
    URL parameter:
      - userId: target user's id to update, must be email format.
    PUT parameters:
      - password: (optional) user's new hashed password.
      - status: (optional) user's new status.
    Response Status Code:
      - 200: success.
      - 400: invalid parameter format, missing header, or missing parameter.
      - 401: JWT auth fail.
      - 403: JWT identify user does not have priviledge.
      - 404: userId does not exist.
    """
    success, errorResponse = _generalVerify(userId, verifyUserIdFormat=True)
    if not success:
        return errorResponse
    # Update data
    conditions = {}
    for c in ('password', 'status'):
        value = request.json.get(c, None)
        if value is not None:
            conditions[c] = value
    try:
        result = User.getById(userId).update_one(**conditions)
    except me.errors.ValidationError as e:
        return constructErrorResponse(
            400, ErrorCode.InvalidParameter,
            'Parameter validation fail: %s' % e.message if GlobalConfig.ServerDebug else '')
    if result == 0:
        # update_one doesn't raise DoesNotExist, so use result count
        return constructErrorResponse(
            404, ErrorCode.UserNotExist,
            'UserId not exist' if GlobalConfig.ServerDebug else '')
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
    except me.errors.DoesNotExist:
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
