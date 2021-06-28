# -*- coding: utf-8 -*-
"""Defines sipmle testing cases for test."""
from datetime import datetime, timedelta
import time
from typing import List, Tuple, Callable
import random
import flask.testing
from api.model import License, Log, LogOperation, User
import api.timefunction
from test.utility import *


def test_auth_admin(createUsers: Tuple[flask.testing.FlaskClient, Callable]) -> None:
    """Test auth user name with password."""
    client, userCreator = createUsers
    users = userCreator(['test1@testing.com', 'test2@testing.com']) # type: List[User]
    result = runAuth(client, payload={
        'userId': 'test1@testing.com',
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    assert len(result.json) == 0, 'auth: unexpected extra response'

    result = runAuth(client, urlLogin='/0', payload={
        'userId': 'test1@testing.com',
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    assert len(result.json) == 0, 'auth: unexpected extra response'

    result = runAuth(client, urlLogin='/1', payload={
        'userId': 'test1@testing.com',
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')

def test_get_user(
    createUsers: Tuple[flask.testing.FlaskClient, Callable]
) -> None:
    """Test get user info."""
    client, userCreator = createUsers
    users = userCreator(['test1@testing.com', 'test2@testing.com']) # type: List[User]
    result = runAuth(client, payload={
        'userId': users[0].uid,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']

    result = runGetUser(client, jwt=jwt)
    verifyResponse(client, result, 200, 'auth', expectedData={
        'createTime': api.timefunction.dateTimeToEpochMS(users[0].createTime),
        'productStatus': users[0].productStatus,
    }, expectDataContains={'lastLoginTime', 'lastLoginIp'})

def test_get_user_new(
    createUsers: Tuple[flask.testing.FlaskClient, Callable],
    removeUsers: flask.testing.FlaskClient,
) -> None:
    """Test get user info."""
    client, userCreator = createUsers
    #users = userCreator(['test1@testing.com', 'test2@testing.com']) # type: List[User]
    userId = 'test1@testing.com'
    result = runAuth(client, payload={
        'userId': userId,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']

    result = runGetUser(client, jwt=jwt)
    user = User.objects(uid=userId).get()
    verifyResponse(client, result, 200, 'auth', expectedData={
        'createTime': api.timefunction.dateTimeToEpochMS(user.createTime),
        'productStatus': user.productStatus,
    }, expectDataContains={'lastLoginTime', 'lastLoginIp'})

def test_buy_license(
    createUsers: Tuple[flask.testing.FlaskClient, Callable],
    clearLicenses: flask.testing.FlaskClient,
    clearLogs: flask.testing.FlaskClient
) -> None:
    """Test buy license"""
    client, userCreator = createUsers
    users = userCreator(['test1@testing.com', 'test2@testing.com']) # type: List[User]

    result = runAuth(client, payload={
        'userId': 'test1@testing.com',
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']

    result = runBuyLicense(client, jwt, payload=[
        {'broker': 'broker1', 'eaId': 'idid1', 'count': 10, 'duration': 10},
        {'broker': 'broker1', 'eaId': 'idid2', 'count': 10, 'duration': 20}
    ])
    print('response: ', result.json)
    verifyResponse(client, result, 200, 'buyLicense')

    users[0].reload()
    # Validate license field
    #licenses = {l.lid: l for l in users[0].license} # type: Dict[str, License]
    licenses = {l.lid: l for l in License.objects(owner=users[0].uid)} # type: Dict[str, License]
    for ds in result.json:
        broker, eaId, duration, ids = ds['broker'], ds['eaId'], ds['duration'], ds['id']
        for id in ids:
            realLicense = licenses.get(id, None)
            assert realLicense is not None, '%s does not in DB' % id
            assert realLicense.broker == broker, \
                '%s broker not match %s != %s' % (id, realLicense.broker, broker)
            assert realLicense.eaId == eaId, \
                '%s eaId not match %s != %s' % (id, realLicense.eaId, eaId)
            assert realLicense.duration == duration, \
                '%s duration not match %d != %d' % (id, realLicense.duration, duration)
    # Validate log field
    logs = Log.objects(user=users[0].uid)
    for log in logs: # type: List[Log]
        assert log.operation == LogOperation.LicenseBuy, \
            'Operation is not correct: %d' % log.operation
        entry = json.loads(log.message)
        broker, eaId, duration = entry['broker'], entry['eaId'], entry['duration']
        buyTime = log.timestamp
        for id in entry['id']:
            realLicense = licenses[id]
            assert realLicense is not None, '%s does not in DB' % id
            assert realLicense.broker == broker, \
                '%s broker not match %s != %s' % (id, realLicense.broker, broker)
            assert realLicense.eaId == eaId, \
                '%s eaId not match %s != %s' % (id, realLicense.eaId, eaId)
            assert realLicense.duration == duration, \
                '%s duration not match %d != %d' % (id, realLicense.duration, duration)
            assert abs((buyTime - realLicense.buyTime).total_seconds()) < 600, \
                '%s buy time not match %s != %s' % (id, str(realLicense.buyTime), str(buyTime))
        assert entry['count'] == len(entry['id'])

def test_buy_license_new(
    createUsers: Tuple[flask.testing.FlaskClient, Callable],
    removeUsers:flask.testing.FlaskClient,
    clearLicenses: flask.testing.FlaskClient,
    clearLogs: flask.testing.FlaskClient
) -> None:
    """Test buy license"""
    client, userCreator = createUsers
    userId = 'test1@testing.com'

    result = runAuth(client, payload={
        'userId': userId,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']

    result = runBuyLicense(client, jwt, payload=[
        {'broker': 'broker1', 'eaId': 'idid1', 'count': 10, 'duration': 10},
        {'broker': 'broker1', 'eaId': 'idid2', 'count': 10, 'duration': 20}
    ])
    print('response: ', result.json)
    verifyResponse(client, result, 200, 'buyLicense')

    user = User.objects(uid=userId).get()
    # Validate license field
    #licenses = {l.lid: l for l in user.license} # type: Dict[str, License]
    licenses = {l.lid: l for l in License.objects(owner=userId)} # type: Dict[str, License]
    for ds in result.json:
        broker, eaId, duration, ids = ds['broker'], ds['eaId'], ds['duration'], ds['id']
        for id in ids:
            realLicense = licenses.get(id, None)
            assert realLicense is not None, '%s does not in DB' % id
            assert realLicense.broker == broker, \
                '%s broker not match %s != %s' % (id, realLicense.broker, broker)
            assert realLicense.eaId == eaId, \
                '%s eaId not match %s != %s' % (id, realLicense.eaId, eaId)
            assert realLicense.duration == duration, \
                '%s duration not match %d != %d' % (id, realLicense.duration, duration)
    # Validate log field
    logs = Log.objects(user=userId)
    for log in logs: # type: List[Log]
        assert log.operation == LogOperation.LicenseBuy, \
            'Operation is not correct: %d' % log.operation
        entry = json.loads(log.message)
        broker, eaId, duration = entry['broker'], entry['eaId'], entry['duration']
        buyTime = log.timestamp
        for id in entry['id']:
            realLicense = licenses[id]
            assert realLicense is not None, '%s does not in DB' % id
            assert realLicense.broker == broker, \
                '%s broker not match %s != %s' % (id, realLicense.broker, broker)
            assert realLicense.eaId == eaId, \
                '%s eaId not match %s != %s' % (id, realLicense.eaId, eaId)
            assert realLicense.duration == duration, \
                '%s duration not match %d != %d' % (id, realLicense.duration, duration)
            assert abs((buyTime - realLicense.buyTime).total_seconds()) < 600, \
                '%s buy time not match %s != %s' % (id, str(realLicense.buyTime), str(buyTime))

def test_get_user_license(
    createUsers: Tuple[flask.testing.FlaskClient, Callable],
    addLicenses: Tuple[flask.testing.FlaskClient, Callable],
    clearLicenses: flask.testing.FlaskClient,
) -> None:
    """Test get user owned license"""
    client, userCreator = createUsers
    _, licenseCreator = addLicenses
    users = userCreator(['test1@testing.com', 'test2@testing.com']) # type: List[User]
    nLicenses = 10000
    licenses = licenseCreator(users[0], nLicenses, 'bk0', 'idid0', 30) # type: List[License]

    result = runAuth(client, payload={
        'userId': users[0].uid,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')

    jwt = result.headers['JWT']
    pageId = ''
    size = 100
    responseLicenses = []
    iteration = 0
    while True:
        result = runGetUserLicense(client, jwt=jwt, payload={'size': size, 'pageId': pageId})
        verifyResponse(client, result, 200, 'getUserLicense')
        if (len(result.json['license']) == 0) or (result.json['nextPage'] == ''):
            break
        print('    Return: ', len(result.json['license']))
        responseLicenses.extend(result.json['license'])
        pageId = result.json['nextPage']
        iteration += 1
        # if iteration > 10:
        #     assert False, 'Too many iteration'
    assert len(responseLicenses) == nLicenses, '# of retrived license not match: %d' % len(responseLicenses)

def test_activate_license(
    createUsers: Tuple[flask.testing.FlaskClient, Callable],
    addProducts: Tuple[flask.testing.FlaskClient, Callable],
    addLicenses: Tuple[flask.testing.FlaskClient, Callable],
    clearLicenses: flask.testing.FlaskClient,
    clearLogs: flask.testing.FlaskClient
) -> None:
    """Test activate license"""
    client, userCreator = createUsers
    _, licenseCreator = addLicenses
    _, productCreator = addProducts
    users = userCreator(['test1@testing.com', 'test2@testing.com']) # type: List[User]
    productCreator(users[0], 'bk0', 'idid0', 'mmm0', api.timefunction.now())
    productCreator(users[0], 'bk0', 'idid0', 'mmmnouse', api.timefunction.now())
    productCreator(users[0], 'bk0', 'ididnouse', 'mmm0', api.timefunction.now())
    productCreator(users[0], 'bk0nouse', 'idid0', 'mmm0', api.timefunction.now())
    licenses = licenseCreator(users[1], 10000, 'bk0', 'idid0', 30) # type: List[License]

    result = runAuth(client, payload={
        'userId': 'test1@testing.com',
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']

    start = time.time()
    targetLicenses = random.sample(range(0, len(licenses)), 100)
    for i in range(len(targetLicenses)):
        targetLicenses[i] = licenses[targetLicenses[i]]
    result = runActivate(
        client, jwt,
        payload=[{'id': l.lid, 'mId': 'mmm0'} for l in targetLicenses])
    print('response: ', result.json)
    verifyResponse(client, result, 200, 'activate')
    assert len(result.json['fail']) == 0
    assert len(result.json['status']) == 1
    end = time.time()
    print('Time: ', end - start)

    buyer = License.objects(owner=users[1].uid)
    activator = User.objects(uid=users[0].uid).get()
    # Validate buyer
    for lic in targetLicenses:
        realLic = buyer.filter(lid=lic.lid).get()
        assert realLic.broker == lic.broker, \
            '%s broker not match %s != %s' % (lic.lid, realLic.broker, lic.broker)
        assert realLic.eaId == lic.eaId, \
            '%s eaId not match %s != %s' % (lic.lid, realLic.eaId, lic.eaId)
        assert realLic.duration == lic.duration, \
            '%s duration not match %d != %d' % (lic.lid, realLic.duration, lic.duration)
        assert realLic.consumer == activator.uid, \
            '%s consumer not match %s != %s' % (lic.lid, realLic.consumer, buyer.uid)
        assert realLic.activationIp != '', \
            '%s invalid activation IP %s' % (lic.lid, realLic.activationIp)
        assert realLic.activationTime.year > 2020, \
            '%s invalid activation time %s' % (lic.lid, str(realLic.activationTime))
    # Validate activator
    gainDays = {(l.broker, l.eaId, 'mmm0'): l.duration for l in targetLicenses}
    for key, value in gainDays.items():
        status = activator.productStatus.filter(broker=key[0], eaId=key[1], mId=key[2]).get()
        assert (status.expireTime - api.timefunction.now() - timedelta(days=value)) < timedelta(hours=1), \
            'Invalid expire time: brk=%s, eaId=%s, mId=%s, due=%s' % (
                status.broker, status.eaId, status.mId, str(status.expireTime))
    # Validate response new status
    for status in result.json['status']:
        realStatus = activator.productStatus.filter(
            broker=status['broker'], eaId=status['eaId'], mId=status['mId']).get()
        returnedExpireTime = api.timefunction.epochMSToDateTime(status['expireTime'])
        assert (realStatus.expireTime == returnedExpireTime), \
            'Invalid expire time: brk=%s, eaId=%s, mId=%s, due=%s' % (
                status.broker, status.eaId, status.mId, str(returnedExpireTime))

def test_get_log(
    createUsers: Tuple[flask.testing.FlaskClient, Callable],
    addLogs: Tuple[flask.testing.FlaskClient, Callable],
    clearLogs: flask.testing.FlaskClient,
) -> None:
    """Test activate license"""
    client, userCreator = createUsers
    _, logCreator = addLogs
    users = userCreator(['test1@testing.com', 'test2@testing.com']) # type: List[User]
    nLogs = 10
    logs = logCreator(users[0], nLogs, LogOperation.LicenseBuy)

    result = runAuth(client, payload={
        'userId': users[0].uid,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']
    startTime = 0
    endTime = api.timefunction.nowUnixEpochMS()
    size = 2
    logs = []
    iteration = 0
    while True:
        print('Use range %d, %d' % (startTime, endTime))
        result = runGetUserLog(
            client, jwt=jwt,
            payload={'size': size, 'startTime': startTime, 'endTime': endTime})
        verifyResponse(client, result, 200, 'log')
        if (len(result.json['log']) == 0) or (result.json['nextTime'] == 0):
            break
        print('    Return: ', len(result.json['log']))
        data = result.json['log']
        assert all(data[i]['timestamp'] >= data[i+1]['timestamp'] for i in range(1,len(data)-1)), \
            'Response log is not decreasing sorted.'
        assert all(
            (data[i]['timestamp'] >= startTime) and (data[i]['timestamp'] < endTime)
            for i in range(len(data))
        ), 'Return timestamp not in range'
        logs.extend(data)
        #startTime = result.json['nextTime']
        endTime = result.json['nextTime']
        iteration += 1
        # if iteration > 10:
        #     assert False, 'Too many iteration'
    assert len(logs) == nLogs, '# of retrived log not match: %d' % len(logs)

def test_register_product(
    createUsers: Tuple[flask.testing.FlaskClient, Callable],
    addProducts: Tuple[flask.testing.FlaskClient, Callable],
    clearLogs: flask.testing.FlaskClient
) -> None:
    """Test register product."""
    client, userCreator = createUsers
    _, productCreator = addProducts
    users = userCreator(['test1@testing.com', 'test2@testing.com']) # type: List[User]
    products = []
    products.append(productCreator(users[0], 'bk0', 'idid0', 'mmm0', api.timefunction.now()))
    products.append(productCreator(users[0], 'bk0', 'idid0', 'mmmnouse', api.timefunction.now()))
    products.append(productCreator(users[0], 'bk0', 'ididnouse', 'mmm0', api.timefunction.now()))
    products.append(productCreator(users[0], 'bk0nouse', 'idid0', 'mmm0', api.timefunction.now()))

    result = runAuth(client, payload={
        'userId': 'test1@testing.com',
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']

    # start = time.time()
    result = runRegisterProduct(
        client, jwt=jwt,
        payload=[{'broker': 'newbroker', 'eaId': 'newid', 'mId': 'newm'}])
    print('response: ', result.json)
    verifyResponse(client, result, 200, 'registerProduct')

def test_register_product_new(
    createUsers: Tuple[flask.testing.FlaskClient, Callable],
    addProducts: Tuple[flask.testing.FlaskClient, Callable],
    removeUsers: flask.testing.FlaskClient,
    clearLogs: flask.testing.FlaskClient,
) -> None:
    """Test register product."""
    client, userCreator = createUsers
    _, productCreator = addProducts
    #users = userCreator(['test1@testing.com', 'test2@testing.com'], True) # type: List[User]
    # products = []
    # products.append(productCreator(users[0], 'bk0', 'idid0', 'mmm0', api.timefunction.now()))
    # products.append(productCreator(users[0], 'bk0', 'idid0', 'mmmnouse', api.timefunction.now()))
    # products.append(productCreator(users[0], 'bk0', 'ididnouse', 'mmm0', api.timefunction.now()))
    # products.append(productCreator(users[0], 'bk0nouse', 'idid0', 'mmm0', api.timefunction.now()))

    result = runAuth(client, payload={
        'userId': 'test1@testing.com',
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']

    # start = time.time()
    result = runRegisterProduct(
        client, jwt=jwt,
        payload=[{'broker': 'newbroker', 'eaId': 'newid', 'mId': 'newm'}])
    print('response: ', result.json)
    verifyResponse(client, result, 200, 'registerProduct')
