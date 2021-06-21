# -*- coding: utf-8 -*-
"""Defines utilities for testing."""
import os
import sys
import random
import string

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
)

import json
from datetime import datetime, timezone
import urllib.parse
import pymongo
import flask
import flask.testing
from api.config import GlobalConfig
from api.model import Status


GeneralHeader = {
    'User-Agent': 'testing-api-user-agent',
    'x-access-apikey': os.getenv('API_KEYS', ''),
    'x-access-name': 'testing-case-api',
    'x-access-version': '0.0.1',
}
DefaultPassword = 'xyzzy'
dbclient = None
testdb = None

def createUser(userId: str, password: str=DefaultPassword, status:int=Status.Enabled) -> None:
    """Directly create user by operating database.
    Do nothing if user already existed.
     :param userId: user's id.
     :param password: password. Use global variable DefaultPassword by default.
     :param status: user default status. Default is enabled.
    """
    global dbclient, testdb
    if dbclient is None:
        dbclient = pymongo.MongoClient(host='localhost', port=27017)
        testdb = dbclient[GlobalConfig.DbName]
    testdb.user.update_one({'_id': userId}, {
        "$set": {
            'password': password, 'status': status,
            'createTime': datetime.now(timezone.utc),
            'lastLoginTime': datetime.fromtimestamp(0, timezone.utc),
            'lastLoginIp': '',
            'availableLicenses': [], 'auth': [],
            'log': [{
                'timestamp': datetime.now(timezone.utc),
                'operation': 16, 'ip': '', 'user': '', 'message': ''
            }]
        }
    }, upsert=True)

def addLog(userId: str, n: int) -> None:
    """Directly add log to user.
    Do nothing if user already existed.
     :param userId: user's id.
     :param password: password. Use global variable DefaultPassword by default.
     :param status: user default status. Default is enabled.
    """
    global dbclient, testdb
    if dbclient is None:
        dbclient = pymongo.MongoClient(host='localhost', port=27017)
        testdb = dbclient[GlobalConfig.DbName]
    payload = []
    now = datetime.now().timestamp() * 1000
    past = now - 60 * 60 * 24 * 30 * 1000
    for i in range(n):
        payload.append({
            'timestamp': datetime.fromtimestamp((past + (now - past) / n * i) * .001, timezone.utc),
            'operation': 16,
            'ip': ''.join(random.choice(string.ascii_lowercase) for x in range(16)),
            'user': 'testing %d' % i
        })
    testdb.user.update_one({'_id': userId}, {
        "$push": {
            'log': { '$each': payload }
        }
    }, upsert=False)

def removeUser(userId: str):
    """Directly remove user by operating database.
    Do nothing if fail.
     :param userId: user's id.
    """
    global dbclient, testdb
    testdb.user.delete_one({'_id': userId})

def verifyResponse(
    client: flask.testing.Client, response: flask.Response,
    expectStatusCode: int, operation: str,
    expectedData: dict={}, expectDataContains: set={}
) -> None:
    """Verify response of previous request.
     :param client: flask testing client instance.
     :param response: flask response instance.
     :param expectStatusCode: expect http response status code.
     :param operation: operation message for logging.
    """
    print(' ======== %s =======' % operation)
    print('Response status code: ', response.status)
    print('Response content type: ', response.content_type)
    try:
        print('Response data as json: ', response.json)
    except:
        print('Response data is not json: ', response.data)
    if 'JWT' in response.headers:
        print('Response JWT: ', response.headers['JWT'])
    else:
        print('Response no JWT')
    assert response.status_code == expectStatusCode, \
        '%s: resp %s != exp %d ' % (operation, response.status, expectStatusCode)
    data = response.json
    for k, v in expectedData.items():
        r = data.get(k, None)
        assert r == v, '%s: response %s, %s != exp %s' % (operation, k, r, v)
    for k in expectDataContains:
        r = data.get(k, None)
        assert r is not None, '%s: %s not in response' % (operation, k)

def runAuth(
    client: flask.testing.FlaskClient, urlLogin: str='', extraUrl: str='',
    payload=None, headers=GeneralHeader
) -> flask.Response:
    """Request POST /auth/<login>
     :param client: flask testing client instance.
     :param urlLogin: url parameter `login` set to 1 or not set.
     :param extraUrl: extra url parameter to be appended.
     :param payload: post payload.
     :param headers: customized header to use.
    """
    return client.post(
        urllib.parse.urljoin('/api/v1/auth' + urlLogin, extraUrl),
        content_type='application/json', headers=headers,
        data=json.dumps(payload))

def runGetUser(
    client: flask.testing.FlaskClient, userId: str, jwt: str, extraUrl='',
    headers=GeneralHeader
) -> flask.Response:
    """Request GET /user/<userId>
     :param client: flask testing client instance.
     :param userId: user's id.
     :param jwt: auth JWT response.
     :param extraUrl: extra url parameter to be appended.
     :param headers: customized header to use.
    """
    if (jwt != '') and (jwt is not None):
        if headers is GeneralHeader:
            headers = GeneralHeader.copy()
        headers['Authorization'] = 'Bearer %s' % jwt
    return client.get(
        urllib.parse.urljoin(
            urllib.parse.urljoin('/api/v1/user/', userId), extraUrl),
        content_type='application/json', headers=headers)

def runCreateUser(
    client: flask.testing.FlaskClient, userId: str, jwt: str, extraUrl='',
    payload=None, headers=GeneralHeader
) -> flask.Response:
    """Request POST /user/<userId>
     :param client: flask testing client instance.
     :param userId: new user's id.
     :param jwt: auth JWT response.
     :param extraUrl: extra url parameter to be appended.
     :param payload: post payload.
     :param headers: customized header to use.
    """
    if (jwt != '') and (jwt is not None):
        if headers is GeneralHeader:
            headers = GeneralHeader.copy()
        headers['Authorization'] = 'Bearer %s' % jwt
    return client.post(
        urllib.parse.urljoin(
            urllib.parse.urljoin('/api/v1/user/', userId), extraUrl),
        content_type='application/json', headers=headers,
        data=json.dumps(payload))

def runModifyUser(
    client: flask.testing.FlaskClient, userId: str, jwt: str, extraUrl='',
    payload=None, headers=GeneralHeader
) -> flask.Response:
    """Request PUT /user/<userId>
     :param client: flask testing client instance.
     :param userId: new user's id.
     :param jwt: auth JWT response.
     :param extraUrl: extra url parameter to be appended.
     :param payload: post payload.
     :param headers: customized header to use.
    """
    if (jwt != '') and (jwt is not None):
        if headers is GeneralHeader:
            headers = GeneralHeader.copy()
        headers['Authorization'] = 'Bearer %s' % jwt
    return client.put(
        urllib.parse.urljoin(
            urllib.parse.urljoin('/api/v1/user/', userId), extraUrl),
        content_type='application/json', headers=headers,
        data=json.dumps(payload))

def runDeleteUser(
    client: flask.testing.FlaskClient, userId: str, jwt: str, extraUrl='',
    payload=None, headers=GeneralHeader
) -> flask.Response:
    """Request DELETE /user/<userId>
     :param client: flask testing client instance.
     :param userId: new user's id.
     :param jwt: auth JWT response.
     :param extraUrl: extra url parameter to be appended.
     :param payload: post payload.
     :param headers: customized header to use.
    """
    if (jwt != '') and (jwt is not None):
        if headers is GeneralHeader:
            headers = GeneralHeader.copy()
        headers['Authorization'] = 'Bearer %s' % jwt
    return client.delete(
        urllib.parse.urljoin(
            urllib.parse.urljoin('/api/v1/user/', userId), extraUrl),
        content_type='application/json', headers=headers,
        data=json.dumps(payload))

def runGetUserLog(
    client: flask.testing.FlaskClient, userId: str, jwt: str, extraUrl='',
    payload=None, headers=GeneralHeader
) -> flask.Response:
    """Request GET /user-log/<userId>
     :param client: flask testing client instance.
     :param userId: new user's id.
     :param jwt: auth JWT response.
     :param extraUrl: extra url parameter to be appended.
     :param payload: post payload.
     :param headers: customized header to use.
    """
    if (jwt != '') and (jwt is not None):
        if headers is GeneralHeader:
            headers = GeneralHeader.copy()
        headers['Authorization'] = 'Bearer %s' % jwt
    return client.get(
        urllib.parse.urljoin(
            urllib.parse.urljoin('/api/v1/user-log/', userId), extraUrl),
        content_type='application/json', headers=headers,
        query_string=payload)

def runBuyLicense(
    client: flask.testing.FlaskClient, userId: str, jwt: str, extraUrl='',
    payload=None, headers=GeneralHeader
) -> flask.Response:
    """Request POST /license/<userId>
     :param client: flask testing client instance.
     :param userId: new user's id.
     :param jwt: auth JWT response.
     :param extraUrl: extra url parameter to be appended.
     :param payload: post payload.
     :param headers: customized header to use.
    """
    if (jwt != '') and (jwt is not None):
        if headers is GeneralHeader:
            headers = GeneralHeader.copy()
        headers['Authorization'] = 'Bearer %s' % jwt
    return client.post(
        urllib.parse.urljoin(
            urllib.parse.urljoin('/api/v1/license/', userId), extraUrl),
        content_type='application/json', headers=headers, data=json.dumps(payload))
