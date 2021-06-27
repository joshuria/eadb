# -*- coding: utf-8 -*-
"""Defines all information querying methods."""
from typing import Dict, List
import json
from flask import Blueprint, jsonify, make_response, Response, request, current_app
from flask_jwt_extended import jwt_required
import mongoengine as me
from .common import generalVerify, constructErrorResponse
from .config import GlobalConfig
from .model import ErrorCode, License, Log, LogOperation, Status, User
from .manager import JwtManager
from . import timefunction

V1Api = Blueprint('V1Api', __name__)


#@V1Api.route('/auth', defaults={'login': 0}, methods=['POST'])
@V1Api.route('/auth', methods=['POST'])
@V1Api.route('/auth/<int:login>', methods=['POST'])
def auth(login: int=0) -> Response:
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
    success, msg = generalVerify(request.headers)
    if not success: return msg
    # Validate parameter
    if request.json is None:
        # When client does not send any payload, request.json will be None
        return constructErrorResponse(
            400, ErrorCode.MissingParameter,
            'Missing userId or password' if GlobalConfig.ServerDebug else ''
        )
    userId = request.json.get('userId', None)
    password = request.json.get('password', None)
    if (userId is None) or (password is None):
        return constructErrorResponse(
            400, ErrorCode.MissingParameter,
            'Missing userId or password' if GlobalConfig.ServerDebug else ''
        )
    ## TODO: auth to firebase
    jwtToken = JwtManager.generateToken(userId)

    # Get user
    # The query & insert may fail when concurrently query the same user, must retry here
    for retry in range(8):
        query = User.objects(uid=userId)
        if login:
            query.only('status', 'createTime', 'productStatus', 'license')
        else:
            query.only('status')
        try:
            user = query.get()
        except me.errors.DoesNotExist:
            # This is new user
            user = User(uid=userId)
            try:
                user.save(force_insert=True)
            except me.errors.NotUniqueError as e:
                # Already exist, retry
                continue
        break
    else:
        # Retry n times but still fail:
        return constructErrorResponse(
            404, ErrorCode.InternalCannotInsertUser,
            'Fail to query/insert user. Please retry.' if GlobalConfig.ServerDebug else ''
        )
    if user.status == Status.Disabled:
        return constructErrorResponse(
            403, ErrorCode.AuthUserDisabled,
            'User is disabled' if GlobalConfig.ServerDebug else ''
        )
    # Success
    if login:
        data = {
            'createTime': user.createTime,
            'productStatus': user.productStatus,
        }
    else:
        data = {}
    response = make_response(jsonify(data), 200)
    response.headers['JWT'] = jwtToken
    return response

@V1Api.route('log', methods=['GET'])
@jwt_required()
def getUserLog() ->  Response:
    """Get user's operation log.
    GET parameter:
      - size: max size of items to return. Default is 32.
      - startTime: starting time in unix epoch (ms), included. Default is 0.
      - endTime: end time in unix epoch (ms), excluded. Default is now.
    Response Status Code:
      - 200: success.
      - 400: invalid parameter format, missing header, or missing parameter.
      - 401: JWT auth fail.
      - 403: user is disabled.
    Response Data:
      - nextEndTime: next query endTime, for paging use.
      - log: array of logs.
          * timestamp: unix epoch timestamp (ms).
          * operation: operation type of this log.
          * ip: IP.
          * message: extra message.
    """
    success, msg = generalVerify(request.headers)
    if not success: return msg
    # Validate parameter
    try:
        size = request.values.get('size', 32, type=int)
        startTime = request.values.get('startTime', 0, type=int)
        endTime = request.values.get('endTime', 0, type=int)
    except ValueError:
        return constructErrorResponse(
            400, ErrorCode.InvalidParameter,
            'Invalid parameter' if GlobalConfig.ServerDebug else ''
        )
    startTime = timefunction.epochMSToDateTime(startTime)
    endTime = timefunction.epochMSToDateTime(endTime) if endTime != 0 else timefunction.now()
    userId = JwtManager.getCurrentUserId()
    current_app.logger.info('Start time: %s, End time: %s', startTime, endTime)
    # query
    result = Log.objects(user=userId, timestamp__gte=startTime, timestamp__lt=endTime) \
        .exclude('id', 'user').limit(size).order_by('-timestamp')
    data = [log.to_mongo() for log in result]
    return make_response(jsonify({
        # 'nextTime': (data[-1]['timestamp'] + timedelta(milliseconds=1)) if len(data) > 0 else 0,
        'nextTime': data[-1]['timestamp'] if len(data) > 0 else 0,
        'log': data
    }), 200)

@V1Api.route('license', methods=['POST'])
@jwt_required()
def buyLicense() -> Response:
    """Buy license for specified user (call by admin only).
    POST parameters:
      + array of the following:
        - broker: broker name.
        - eaId: eaId.
        - count: # of specified (broker, eaId) licenses to buy.
        - duration: duration day of license. Default is 30 days.
    Response Status Code:
      - 200: success.
      - 400: invalid parameter format, missing header, or missing parameter.
      - 401: JWT auth fail.
      - 403: Client has no privildge to do this operation.
    Response Data:
      - count: # of success added licenses.
      - result: array.
          * result.id: license ID.
          * result.broker: broker of this license.
          * result.eaId: EAId of this license.
          * result.duration: duration of this license.
    """
    success, msg = generalVerify(request.headers, adminOnly=True)
    if not success: return msg
    # Validate parameters
    req = request.json # type: List[Dict[str, int|str]]
    if req is None:
        # When client does not send any payload, request.json will be None
        return constructErrorResponse(
            400, ErrorCode.MissingParameter,
            'Missing parameter' if GlobalConfig.ServerDebug else ''
        )
    userId = JwtManager.getCurrentUserId()
    # Get user, prevent user data is not in our database
    logger = current_app.logger
    logger.info('[buyLicense] User %s request buy license.' % userId)
    buyTime = timefunction.now()
    responseData = []
    for order in req:
        # Skip invalid record,
        count, broker = order.get('count', 0), order.get('broker', '').strip()
        eaId, duration = order.get('eaId', '').strip(), order.get('duration', 30)
        # keep count, duration type is int
        try:
            count = int(count)
            duration = int(duration)
        except ValueError:
            logger.warning(
                '[buyLicense]    request %s fail, cannot convert count/duration to int.',
                json.dumps(order)
            )
            continue
        if (count <= 0) or (broker == '') or (eaId == '') or (duration <= 0):
            logger.warning(
                '[buyLicense]    request %s fail, invalid value.',
                json.dumps(order)
            )
            continue
        newLicenses = [
            License(
                broker=broker, eaId=eaId, duration=duration,
                owner=userId, buyTime=buyTime
            ) for i in range(count)]
        License.objects.insert(newLicenses)
        # updateCount = User.objects(uid=userId).update_one(
        #     upsert=True,
        #     push_all__license=newLicenses,
        # )
        # if updateCount <= 0:
        #     logger.warning(
        #         '[buyLicense]    request %s fail, cannot update to DB.',
        #         json.dumps(order)
        #     )
        #     continue
        Log(user=userId, operation=LogOperation.LicenseBuy, ip=request.remote_addr,
            timestamp=buyTime, message=json.dumps({
                'broker': broker, 'eaId': eaId, 'count': count, 'duration': duration,
                'id': [id.lid for id in newLicenses]
            }))

        logger.info('[buyLicense]    request %s success.' % json.dumps(order))
        responseData.append({
            'broker': broker, 'eaId': eaId, 'duration': duration,
            'id': [id.lid for id in newLicenses]
        })
    return make_response(jsonify(responseData), 200)

@V1Api.route('activate', methods=['POST'])
@jwt_required()
def activateLicense() -> Response:
    """Activate a list of licenses.
    POST parameter:
      + array of the following:
        - id: license id to use.
        - mtId: the related mtid to identify which product to activate.
    Response Status Code:
      - 200: success (Need to check response data)
      - 400: if missing header or missing parameter.
      - 401: JWT auth fail.
      - 403: Client has no privilege to perform this operation.
    Response Data:
      + status: array of affected product status.
        - broker: broker name.
        - eaId: EA id.
        - mtId: product id of.
        - expireTime: new expire time in UTC.
      + fail: array of failed licenses.
        - id: failed license's id.
        - code: fail error code.
        - message: extra message.
    """
    success, msg = generalVerify(request.headers)
    if not success: return msg
    # Validate parameters
    req = request.json # type: List[Dict[str, str]]
    if req is None:
        return constructErrorResponse(
            400, ErrorCode.MissingParameter,
            'Missing parameter' if GlobalConfig.ServerDebug else ''
        )
    # Get current user's product status
    userId = JwtManager.getCurrentUserId()
    logger = current_app.logger
    logger.info('[activate] User %s request activate.' % userId)
    try:
        user = User.objects(uid=userId).only('productStatus').get() # type: User
    except me.errors.DoesNotExist:
        logger.warning(
            '[activate]    User %s does not exist in DB, so no matching product status', userId
        )
        return  constructErrorResponse(
            409, ErrorCode.LicenseNotMatchToUserState,
            'User %s does not exist in DB, so no matching product status' % userId
                if GlobalConfig.ServerDebug else ''
        )
    # Build a lookup table
    activateTime = timefunction.now()
    newStatus = {}
    failLicense = []
    # Do operation
    for order in req:
        if type(order) is not dict:
            continue
        lid, mId = order.get('id', None), order.get('mId', None)
        if (lid is None) or (mId is None):
            continue
        # Get current license and productStatus
        try:
            license = License.objects(lid=lid).get() # type: License
        except me.errors.DoesNotExist:
            failLicense.append({
                'id': lid, 'code': ErrorCode.LicenseActivatedOrNotExist,
                'message': '%s is activated or not found' % lid
            })
            logger.warning('[activate]    %s is activated or not found' % lid)
            continue
        if license.consumer != '':
            failLicense.append({
                'id': lid, 'code': ErrorCode.LicenseActivatedOrNotExist,
                'message': '%s is activated or not found' % lid
            })
            logger.warning('[activate]    %s is activated or not found' % lid)
            continue

        # result = User.objects.aggregate([
        #     {'$match': {'$and': [
        #         {'license': { '$elemMatch': { '_id': lid, 'consumer': ''}}}
        #     ]}},
        #     {'$redact': {
        #         '$cond': {
        #             'if': { '$or': [
        #                 {'$eq': [ '$_id', lid ]},
        #                 {'$gt': [ {'$size': {'$ifNull': ['$license', []]}}, 0] }
        #             ]},
        #             'then': '$$DESCEND', 'else': '$$PRUNE'
        #         }
        #     }},
        #     {'$unwind': '$license'},
        #     {'$replaceRoot': {'newRoot': '$license'}}
        # ])
        # license = None
        # for u in result:
        #     license = License.fromDict(u)
        # if license is None:
        #     failLicense.append({
        #         'id': lid, 'code': ErrorCode.LicenseActivatedOrNotExist,
        #         'message': '%s is activated or not found' % lid
        #     })
        #     logger.warning('[activate]    %s is activated or not found' % lid)
        #     continue

        try:
            productStatus = user.productStatus \
                .filter(broker=license.broker, eaId=license.eaId, mId=mId) \
                .get()
        except me.errors.DoesNotExist:
            failLicense.append({
                'id': lid, 'code': ErrorCode.LicenseNotMatchToUserState,
                'message': '%s user %s has no product broker=%s, eaId=%s, mId=%s' %
                    (lid, userId, license.broker, license.eaId, mId)
                })
            logger.warning(
                '[activate]    %s user %s has no product broker=%s, eaId=%s, mId=%s',
                lid, userId, license.broker, license.eaId, mId
            )
            continue
        # Update license
        license.consumer = userId
        license.activationTime = activateTime
        license.activationIp = request.remote_addr
        license.save()
        # # We need operate this way to prevent concurrent activation on the same license
        # r = User.objects(license__match={'lid': lid, 'consumer': ''}).update_one(
        #     upsert=False,
        #     set__license__S__consumer=userId,
        #     set__license__S__activationTime=activateTime,
        #     set__license__S__activationIp=request.remote_addr
        # )
        # if r < 1:
        #     logger.warning('[activate]    %s activated or not found.' % lid)
        #     failLicense.append({
        #         'id': lid, 'code': ErrorCode.LicenseActivatedOrNotExist,
        #         'message': '%s activated or not found' % lid
        #     })
        #     continue

        # Update product state and write log
        newExpireTime = timefunction.addDay(productStatus.expireTime, license.duration)
        r = User.objects(
                uid=userId,
                productStatus__match={'broker': license.broker, 'eaId': license.eaId, 'mId': mId}
            ).update_one(
                upsert=False,
                set__productStatus__S__expireTime=newExpireTime,
            )
        if r < 1:
            logger.fatal(
                '[activate]    %s user %s with product status not found, broker=%s, eaId=%s, mId=%s',
                lid, userId, license.broker, license.eaId, mId
            )
            failLicense.append({
                'id': lid, 'code': ErrorCode.LicenseConsumedButActivateToDBFail,
                'message': 'License %s user %s with product status not found, broker=%s, eaId=%s, mId=%s' %
                    (lid, userId, license.broker, license.eaId, mId)
            })
            continue
        # Write log
        Log(
            user=userId, operation=LogOperation.LicenseActivate, ip=request.remote_addr,
            timestamp=activateTime, message=json.dumps({
                'id': license.lid,
                'broker': license.broker, 'eaId': license.eaId, 'duration': license.duration,
                'newExpireTime': timefunction.dateTimeToEpochMS(newExpireTime)
            })).save()

        newStatus[(license.broker, license.eaId, mId)] = newExpireTime
        logger.info('[activate]    %s activated success' % lid)

    return make_response(
        jsonify({
            'status': [{
                'broker': s[0], 'eaId': s[1], 'mId': s[2], 'expireTime': expireTime
            } for s, expireTime in newStatus.items()],
            'fail': failLicense
        }), 200
    )
