# -*- coding: utf-8 -*-
"""Defines utilities for testing."""
import os
import sys
import random

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
)

from typing import Dict, Tuple, List
import string
import json
from datetime import datetime, timezone
import urllib.parse
import pytest
import flask
import flask.testing
from mongoengine.errors import DoesNotExist, NotUniqueError
from api.config import GlobalConfig
from api.model import User, Status, License, Log, LogOperation, ProductStatus
from api.timefunction import dateTimeToEpochMS, now, ZeroDateTime
from test.conftest import client


GeneralHeader = {
    'User-Agent': 'testing-api-user-agent',
    'x-access-apikey': os.getenv('API_ADMIN_KEY', ''),
    'x-access-name': 'testing-case-api',
    'x-access-version': '0.0.1',
}
DefaultPassword = 'xyzzy'


def getUser(userId: str) -> User:
    """Get user instance."""
    try:
        return User.objects(uid=userId).get()
    except DoesNotExist:
        return None

@pytest.fixture(scope='function')
def createUsers(client: flask.testing.FlaskClient):
    """Create a list of users.
    Do nothing if user already existed.
     :param client: flask testing client instance.
    """
    users = []
    skipRemove = [False]
    def _m(info: List[Tuple[str, Status]], noRemove: bool=False) -> List[User]:
        """ Create user real implement.
         :param info: list of user info. Each user info is a tuple contains:
            - user's id.
            - user default status. Default is enabled.
         :return: list of created user instances.
        """
        print('Fixture:: Create Users %s' % ('without removing' if noRemove else ''))
        skipRemove[0] = noRemove
        for u in info:
            if type(u) is not Tuple:
                u = u, Status.Enabled
            user = User(uid=u[0], status=u[1])
            try:
                user.save(force_insert=True)
            except NotUniqueError:
                print('CreateUsers: user %s already exist.' % u[0])
                user = User.objects(uid=u[0]).get()
            users.append(user)
        return users
    # Call next
    yield client, _m
    # Finalize
    if skipRemove[0]:
        print('Fixture:: Create Users skip removing %d users' % len(users))
    else:
        print('Fixture:: Create Users finalize remove %d users' % len(users))
        for u in users:
            u.delete()

@pytest.fixture(scope='function')
def removeUsers(client: flask.testing.FlaskClient):
    """Remove dynamic created users after test (teardown).
    Do nothing if user already existed.
     :param client: flask testing client instance.
    """
    users = []
    def _m(info: List[str]) -> None:
        """Register user ids to be removed when teardown.
         :param info: user id list.
         :return: list of created user instances.
        """
        users.extend(info)
    # Call next
    yield client, _m
    # Finalize
    print('Fixture:: Remove Users remove %d users' % len(users))
    for u in users:
        if type(u) is User:
            u.delete()
        else:
            User.objects(uid=u).delete()

@pytest.fixture(scope='function')
def addLogs(client: flask.testing.FlaskClient) -> None:
    """Add n logs.
     :param client: flask testing client instance.
    """
    def _m(user: User, n: int, op: LogOperation) -> List[Log]:
        """Add logs implementation.
         :param n: # of logs to add.
         :param op: operation code of each log.
        """
        print('Fixture: Call Add Logs')
        if type(user) is User:
            user = user.uid
        payload = []
        now = datetime.now().timestamp()
        past = now - 60 * 60 * 24 * 30
        for i in range(n):
            payload.append(Log(
                user=user,
                timestamp=datetime.fromtimestamp(past + (now - past) / n * i, timezone.utc),
                operation=op,
                ip=''.join(random.choice(string.ascii_lowercase) for x in range(16)),
                message='Manually added log!!'
            ))
        # push_all will reverse order?
        Log.objects.insert(payload)
        #User.objects(uid=user).update_one(push_all__log=payload)
        return payload
    yield client, _m

@pytest.fixture(scope='function')
def clearLogs(client: flask.testing.FlaskClient) -> None:
    """Add n logs.
     :param client: flask testing client instance.
    """
    yield client
    print('Fixture: Clear Logs')
    Log.drop_collection()

@pytest.fixture(scope='function')
def addProducts(client: flask.testing.FlaskClient) -> None:
    """Add n productStatus to user.
     :param client: flask testing client instance.
    """
    def _m(user: User, broker: str, eaId: str, mId: str, expireTime: datetime) -> ProductStatus:
        """Add logs implementation.
         :param n: # of logs to add.
         :param broker: broker name.
         :param eaId: id of ea.
         :param mId: the mId.
         :param expireTime: expire time in UTC of this product.
        """
        print('Fixture: Call Add Products')
        status = ProductStatus(broker=broker, eaId=eaId, mId=mId, expireTime=expireTime)
        if type(user) is User:
            User.objects(uid=user.uid).update_one(push__productStatus=status)
        else:
            User.objects(uid=user).update_one(push__productStatus=status)
        return status
    yield client, _m

@pytest.fixture(scope='function')
def addLicenses(client: flask.testing.FlaskClient) -> None:
    """Add n licenses to user.
     :param client: flask testing client instance.
    """
    def _m(user: User, n: int, broker: str, eaId: str, duration=30) -> List[License]:
        """Add logs implementation.
         :param n: # of logs to add.
         :param broker: broker name.
         :param eaId: id of ea.
         :param duration: duration day of added licenses.
        """
        print('Fixture: Call Add Licenses')
        payload = []
        if type(user) is User:
            user = user.uid
        # now = datetime.now().timestamp()
        # past = now - 60 * 60 * 24 * 30
        for i in range(n):
            payload.append(License(
                broker=broker, eaId=eaId, owner=user, duration=duration
            ))
        User.objects(uid=user).update_one(push_all__license=payload)
        return payload
    yield client, _m

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
        print('Response data as json: ', json.dumps(response.json, indent=4))
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
    client: flask.testing.FlaskClient, jwt: str, extraUrl='',
    payload=None, headers=GeneralHeader
) -> flask.Response:
    """Request GET /log
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
        urllib.parse.urljoin('/api/v1/log', extraUrl),
        headers=headers, query_string=payload)

def runBuyLicense(
    client: flask.testing.FlaskClient, jwt: str, extraUrl='',
    payload=None, headers=GeneralHeader
) -> flask.Response:
    """Request POST /license
     :param client: flask testing client instance.
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
        urllib.parse.urljoin('/api/v1/license', extraUrl),
        content_type='application/json', headers=headers, data=json.dumps(payload))

def runGetLicense(
    client: flask.testing.FlaskClient, userId: str, jwt: str, extraUrl='',
    payload=None, headers=GeneralHeader
) -> flask.Response:
    """Request GET /license/<userId>
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
            urllib.parse.urljoin('/api/v1/license/', userId), extraUrl),
        content_type='application/json', headers=headers,
        query_string=payload)

def runQueryLicense(
    client: flask.testing.FlaskClient, jwt: str, extraUrl='',
    payload=None, headers=GeneralHeader
) -> flask.Response:
    """Request POST /query-license
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
            urllib.parse.urljoin('/api/v1/query-license', extraUrl),
        content_type='application/json', headers=headers, data=json.dumps(payload))

def runActivate(
    client: flask.testing.FlaskClient, jwt: str, extraUrl='',
    payload=None, headers=GeneralHeader
) -> flask.Response:
    """Request POST /activate
     :param client: flask testing client instance.
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
        urllib.parse.urljoin('/api/v1/activate', extraUrl),
        content_type='application/json', headers=headers, data=json.dumps(payload))
