# -*- coding: utf-8 -*-
"""Defines all information querying methods."""
import json
from datetime import timedelta
from typing import Tuple
from flask import Blueprint, jsonify, make_response, request
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required
import mongoengine as me
from mongoengine.errors import DoesNotExist
from pymongo.collection import ReturnDocument
from .common import verifyHeader, sendMail
from .config import GlobalConfig
from .database import constructErrorResponse
from .model import ErrorCode, License, Log, LogOperation, Status, User
from .timefunction import ZeroDateTime, epochMSToDateTime, now

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
    """Create a new user (call by admin only).
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
    success, errorResponse = _generalVerify(userId)
    if not success:
        return errorResponse
    # Update data
    conditions = {}
    for c in ('password', 'status'):
        value = request.json.get(c, None)
        # TODO: verify password must not empty
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
    """Modify user's data (call by admin only).
     :param userId: user's id.
    URL parameter:
      - userId: target user's id to update, must be email format.
    Response Status Code:
      - 200: success.
      - 400: invalid parameter format, missing header, or missing parameter.
      - 401: JWT auth fail.
      - 403: JWT identify user does not have priviledge.
      - 404: userId does not exist.
    """
    success, errorResponse = _generalVerify(userId, adminOnly=True)
    if not success:
        return errorResponse
    # Update data
    result = User.getById(userId).delete()
    if result == 0:
        # delete doesn't raise DoesNotExist, so use result count
        return constructErrorResponse(
            404, ErrorCode.UserNotExist,
            'UserId not exist' if GlobalConfig.ServerDebug else '')
    # TODO: write delete log
    return make_response(jsonify({}), 200)

@V1Api.route('user-log/<userId>', methods=['GET'])
@jwt_required()
def getUserLog(userId: str):
    """Get user's operation log.
     :param userId: user's id.
    URL parameter:
      - userId: target user's id to update, must be email format.
    GET parameter:
      - size: max size of items to return. Default is 32.
      - startTime: starting time in unix epoch (ms), included.
      - endTime: end time in unix epoch (ms), excluded. Default is now.
    Response Status Code:
      - 200: success.
      - 400: invalid parameter format, missing header, or missing parameter.
      - 401: JWT auth fail.
      - 403: JWT identify user does not have priviledge.
      - 404: userId does not exist.
    Response Data:
      - remain: remaining logs count.
      - result: array of log.
          * result.timestamp: unix epoch timestamp (ms).
          * operation: operation type of this log.
          * ip: IP.
          * user: extra joined user.
          * message: extra message.
    """
    success, errorResponse = _generalVerify(userId)
    if not success:
        return errorResponse
    # Parameters
    size = request.values.get('size', 32, type=int)
    startTime = request.values.get('startTime', None, type=float)
    endTime = request.values.get('endTime', None, type=float)
    if startTime is None:
        return constructErrorResponse(
            400, ErrorCode.InvalidParameter,
            'Missing startTime' if GlobalConfig.ServerDebug else '')
    startTime = epochMSToDateTime(startTime)
    endTime = now() \
        if (endTime is None) or (endTime == 0) \
        else epochMSToDateTime(endTime)
    # Check user exist
    # TODO
    # endTime < startTime: return nothing
    if endTime < startTime:
        return make_response(jsonify({'remain': 0, 'result': []}), 200)
    # Do query
    result = User.objects.aggregate([
        {'$match': { '_id': userId }},
        {'$unwind': '$log'},
        {'$match': { 'log.timestamp': {'$gte': startTime, '$lt': endTime}}},
        {'$project': {'_id': 0, 'log': 1}},
        {'$sort': {'log.timestamp': -1}},
        {'$limit': size},
    ])
    result = [l['log'] for l in result]
    return make_response(jsonify({'remain': len(result), 'result': result}), 200)

@V1Api.route('license/<userId>', methods=['POST'])
@jwt_required()
def buyLicense(userId: str):
    """Buy license for specified user (call by admin only).
     :param userId: user's id.
    URL parameter:
      - userId: user's id to query. This is limited to use email format.
    POST parameters:
      - param: array of data.
      - param.eaType: type of EA to buy.
      - param.count: # of licenses of specified EAType to buy.
      - param.duration: duration day of license. Default is 30 days.
    Response Status Code:
      - 200: success.
      - 400: invalid parameter format, missing header, or missing parameter.
      - 401: JWT auth fail.
      - 403: JWT identify user does not have priviledge.
      - 409: userId already exist.
    Response Data:
      - count: # of success added licenses.
      - result: array.
          * result.id: license ID.
          * result.eaType: EAType of this license.
          * result.duration: duration of this license.
    """
    success, errorResponse = _generalVerify(userId, adminOnly=True)
    if not success:
        return errorResponse
    # Verify other fields
    param = request.json.get('param', None)
    if param is None:
        return constructErrorResponse(
            400, ErrorCode.MissingParameter,
            'Missing parameter' if GlobalConfig.ServerDebug else '')
    #try:
    #    param = json.loads(param)
    #except JSONDecodeError:
    #    return constructErrorResponse(
    #        400, ErrorCode.InvalidParameter,
    #        'Invalid parameter' if GlobalConfig.ServerDebug else '')

    userQuery = User.getById(userId)
    ## Check user exist <- delegate to userId
    #try:
    #    u = userQuery.only('_id').get()
    #    print(u)
    #except DoesNotExist:
    #    return constructErrorResponse(
    #        404, ErrorCode.UserNotExist,
    #        'UserId not exist' if GlobalConfig.ServerDebug else '')
    result = []
    buyTime = now()
    for record in param:
        # Skip invalid record
        if ('count' not in record) or ('eaType' not in record):
            continue
        try:
            count = int(record['count'])
        except ValueError:
            # type of count cannot be convert to int
            continue
        eaType = record['eaType']
        # TODO: check eaType
        duration = record['duration'] if 'duration' in record \
            else GlobalConfig.AppDefaultLicenseDurationDay
        if (count <= 0) or (duration <= 0):
            continue
        licenses = [
            License(
                lid=License.generateId(),
                eaType=eaType,
                durationDay=duration,
                owner=userId,
                buyTime=buyTime)
            for i in range(count)]
        # Insert into user's availableLicense (licenses)
        updateCount = userQuery.update_one(
            push_all__availableLicenses=licenses,
            push__log=Log(
                timestamp=buyTime,
                operation=LogOperation.LicenseBuy,
                ip='',
                message=json.dumps([{
                    'id': l.lid, 'eaType': l.eaType, 'duration': l.durationDay
                } for l in licenses])))
        print(updateCount)
        for lic in licenses:
            result.append({'id': lic.lid, 'eaType': eaType, 'duration': duration})
    sendMail(userId, 'testing titile', 'this is body: ' + userId)
    return make_response(jsonify({'count': len(result), 'result': result}), 200)

@V1Api.route('license/<userId>', methods=['GET'])
@jwt_required()
def getUserLicense(userId: str):
    """Get user's all available (not activated) licenses.
     :param userId: user's id.
    URL parameter:
      - userId: target user's id to update, must be email format.
    GET parameter:
      - size: max size of items to return. Default is 32.
      - startTime: starting time in unix epoch (ms), included.
      - endTime: end time in unix epoch (ms), excluded. Default is now.
    Response Status Code:
      - 200: success.
      - 400: invalid parameter format, missing header, or missing parameter.
      - 401: JWT auth fail.
      - 403: JWT identify user does not have priviledge.
      - 404: userId does not exist.
    Response Data:
      - remain: remaining logs count.
      - result: array of log.
          * result.timestamp: unix epoch timestamp (ms).
          * operation: operation type of this log.
          * ip: IP.
          * user: extra joined user.
          * message: extra message.
    """
    success, errorResponse = _generalVerify(userId)
    if not success:
        return errorResponse
    # Parameters
    size = request.values.get('size', 32, type=int)
    startTime = request.values.get('startTime', None, type=float)
    endTime = request.values.get('endTime', None, type=float)
    if startTime is None:
        return constructErrorResponse(
            400, ErrorCode.InvalidParameter,
            'Missing startTime' if GlobalConfig.ServerDebug else '')
    startTime = epochMSToDateTime(startTime)
    endTime = now() \
        if (endTime is None) or (endTime == 0) \
        else epochMSToDateTime(endTime)
    # Check user exist
    # TODO
    print(startTime.timestamp(), endTime.timestamp())
    # endTime < startTime: return nothing
    if endTime < startTime:
        return make_response(jsonify({'remain': 0, 'result': []}), 200)
    # Do query
    result = User.objects.aggregate([
        {'$match': { '_id': userId }},
        {'$unwind': '$licenses'},
        {'$match': { 'licenses.buyTime': {'$gte': startTime, '$lt': endTime}}},
        {'$project': {'_id': 0, 'licenses': 1}},
        {'$sort': {'licenses.buyTime': -1}},
        {'$limit': size},
    ])
    result = [l['licenses'] for l in result]
    return make_response(jsonify({'remain': len(result), 'result': result}), 200)

@V1Api.route('query-license', methods=['POST'])
@jwt_required()
def queryLicenseStatus():
    """Query given list of licenses status.
     :note: this method can be called by admin only.
    POST parameter:
      - param: array of license ids to query. Only first 32 items will be processed. The value '32'
            is defined in GlobalConfig.AppMaxQueryLicenseSize.
    Response Status Code:
      - 200: success.
      - 400: if missing header or missing parameter.
      - 401: JWT auth fail.
      - 403: User has no privilege to perform this operation.
    Response Data:
      - result: array of only founded licenses.
          * result.id: license id.
          * result.duration: duration in day.
          * result.eaType: EA type of this license.
          * result.owner: owner id.
          * result.buyTime: buy time in unix epoch (ms).
          * result.activationTime: license activation time in unix epoch time (ms).
                0 means not activated.
          * result.activationIp: activation user's IP.
          * result.consumer: activation user's id.
    """
    success, errorResponse = _generalVerify(
        GlobalConfig.DbDefaultAdmin, verifyUserIdFormat=False, adminOnly=True)
    if not success:
        return errorResponse
    requestIds = request.json.get('param', None)
    if requestIds is None:
        return constructErrorResponse(
            400, ErrorCode.InvalidParameter,
            'Missing license id list' if GlobalConfig.ServerDebug else '')
    # Aggregate license ids
    requestIds = requestIds[:GlobalConfig.AppMaxQueryLicenseSize]
    # Do query
    result = User.objects.aggregate([
        {'$project': {'_id': 0, 'licenses': 1}},
        {'$unwind': '$licenses'},
        {'$match': { 'licenses.lid': {'$in': requestIds}}},
    ])
    result = [l['licenses'] for l in result]
    return make_response(jsonify({'result': result}), 200) if success else errorResponse

@V1Api.route('activate/<userId>', methods=['POST'])
@jwt_required()
def activateLicense(userId: str):
    """Activate a list of licenses.
     :note: this method can be called by admin only.
    POST parameter:
      - param: array of license ids to use. Only first 32 items will be processed. The value '32'
            is defined in GlobalConfig.AppMaxQueryLicenseSize.
    Response Status Code:
      - 200: success.
      - 400: if missing header or missing parameter.
      - 401: JWT auth fail.
      - 403: User has no privilege to perform this operation.
      - 404: userId does not exist.
      - 409: some licenses are used.
    Response Data:
      - result: array of updated EA status.
          * result.id: license id.
          * result.duration: duration in day.
          * result.eaType: EA type of this license.
          * result.owner: owner id.
          * result.buyTime: buy time in unix epoch (ms).
          * result.activationTime: license activation time in unix epoch time (ms).
                0 means not activated.
          * result.activationIp: activation user's IP.
          * result.consumer: activation user's id.
    """
    success, errorResponse = _generalVerify(userId, verifyUserIdFormat=False)
    if not success:
        return errorResponse
    requestIds = request.json.get('param', None)
    if requestIds is None:
        return constructErrorResponse(
            400, ErrorCode.InvalidParameter,
            'Missing license id list' if GlobalConfig.ServerDebug else '')
    # Do operation
    eaStatus = {}
    licenseResult = []
    currentTime = now()
    for lid in requestIds[:GlobalConfig.AppMaxQueryLicenseSize]:
        user = User.getById(userId).get()
        if len(user.eaStatus) > 0:
            print('Origin: ', user.eaStatus[0].expireTime)
        else:
            print('Origin: NO data')
        # Update license data
        lidResult = User.objects._collection \
            .find_one_and_update(
                {
                    '_id': userId,
                    'licenses': {'$elemMatch': {'lid': lid}}
                },
                {
                    '$set': {
                        'licenses.$.activationTime': currentTime,
                        'licenses.$.activationIp': request.remote_addr,
                        'licenses.$.consumer': userId,
                    },
                },
                projection={'licenses': {'$elemMatch': {'lid': lid}}, 'eaStatus': 1},
                return_document=ReturnDocument.AFTER)
        print('lidResult', lidResult)
        if (lidResult is None) or ('licenses' not in lidResult):
            licenseResult.append({'id': lid, 'result': ErrorCode.LicenseNotExist})
            continue
        eaType = lidResult['licenses'][0]['eaType']
        duration = lidResult['licenses'][0]['duration']
        # Update EA status
        for status in lidResult['eaStatus']:
            if status['eaType'] != eaType:
                continue
            # Found EA status record, update it
            dueTime = status['expireTime'] + timedelta(days=duration)
            statusResult = User.objects._collection \
                .find_one_and_update(
                    {
                        '_id': userId,
                        'eaStatus': {'$elemMatch': {'eaType': eaType}}
                    },
                    {
                        '$set': {
                            'eaStatus.$.expireTime': dueTime
                        },
                    },
                    projection={'eaStatus': {'$elemMatch': {'eaType': eaType}}},
                    return_document=ReturnDocument.AFTER)
            print(' =====> Update EA status', statusResult)
            break
        else:
            # EA status does not exist, add it
            statusResult = User.objects._collection \
                .find_one_and_update(
                    {
                        '_id': userId,
                        'eaStatus': {'$not': {'$elemMatch': {'eaType': eaType}}}
                    },
                    {
                        '$addToSet': {
                            'eaStatus': {
                                'eaType': eaType,
                                'expireTime': currentTime + timedelta(days=duration)
                            }
                        },
                    },
                    projection={'eaStatus': {'$elemMatch': {'eaType': eaType}}},
                    return_document=ReturnDocument.AFTER)
            print(' =====> Create EA status', statusResult)

        ## Add EA status if not exist
        ## Update EA status
        #statusResult = User.objects.aggregate([
        #    {'$match': { '_id': userId }},
        #    {'$unwind': '$eaStatus'},
        #    {'$match': {'eaStatus.eaType': eaType}},
        #    #{'$set': {'eaStatus.expireTime': {'$add': ['$eaStatus.expireTime', duration]}}},
        #    {'$set': {'eaStatus.expireTime': {'$add': ['$eaStatus.expireTime', 99999999999]}}},
        #    {'$project': {'_id': 0, 'eaStatus': 1}},
        #])
        #
        currentStatus = None
        for s in statusResult['eaStatus']:
            if s['eaType'] != eaType:
                continue
            currentStatus = s
            break
        else:
            # No EA type responsed, should be fail
            print('License %s activation fail on user %s' % (lid, userId))
            licenseResult.append({'id': lid, 'result': ErrorCode.LicenseConsumedButActivateFail})
            continue

        # TODO validate expire time is correct

        licenseResult.append({'id': lid, 'result': ErrorCode.NoError})
        eaStatus[eaType] = currentStatus['expireTime']

    return make_response(jsonify({
        'eaStatus': [{'eaType': key, 'expireTime': value} for key, value in eaStatus.items()],
        'license': licenseResult
    }), 200) if success else errorResponse
