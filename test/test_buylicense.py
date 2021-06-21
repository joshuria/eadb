# -*- coding: utf-8 -*-
import json
from json.decoder import JSONDecodeError
import flask, flask.testing
import pytest
from datetime import datetime
from api.config import GlobalConfig
from api.timefunction import nowUnixEpochMS
from api.model import LogOperation
from utility import DefaultPassword, runAuth, runBuyLicense, runGetUserLog, verifyResponse
from utility import createUser, removeUser


def setup_function() -> None:
    """Testing setup."""
    createUser('test1@testing.com', DefaultPassword)
    createUser('test2@testing.com', DefaultPassword)

def teardown_function() -> None:
    """Testing teardown."""
    removeUser('test1@testing.com')
    removeUser('test2@testing.com')

def verifyResponseAndLog(
    buyResponse: flask.Response, logResponse: flask.Response
) -> None:
    """Verify buy license response with log response."""
    buySet = set([
        (l['id'], l['eaType'], l['duration'])
        for l in buyResponse.json.get('result')])
    logSet = set()
    for l in logResponse.json.get('result'):
        if l['operation'] != LogOperation.LicenseBuy:
            continue
        msg = json.loads(l['message'])
        for i in msg:
            logSet.add((i['id'], i['eaType'], i['duration']))
    assert len(logSet - buySet) == 0, 'Buy response != log record'

def test_buy_license_no_auth_invalid_format(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test with no auth and invalid format."""
    result = runBuyLicense(client, 'nonono', '',
        payload={'param': [
            {'eaType': 111, 'count': 3 }
        ]})
    verifyResponse(client, result, 401, 'buy-license')

def test_buy_license_no_auth(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test with no auth."""
    timeRange = (datetime.utcnow().timestamp() * 1000, 0)
    size = 100
    result = runBuyLicense(client, GlobalConfig.DbDefaultAdmin, '',
        payload={'param': [
            {'eaType': 111, 'count': 3 }
        ]})
    verifyResponse(client, result, 401, 'buy-license')

def test_buy_license_wrong_auth_header(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test invalid header."""
    timeRange = (datetime.utcnow().timestamp() * 1000, 0)
    size = 100
    result = runBuyLicense(
        client, 'nonono', 'fdj;fklasdjf9iopqwejfl;asdkfasdjf.werwqer.2282828',
        payload={'param': [
            {'eaType': 111, 'count': 3 }
        ]})
    verifyResponse(client, result, 401, 'buy-license')

def test_buy_license_admin(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test admin create already exist user."""
    result = runAuth(client, payload={
        'userId': GlobalConfig.DbDefaultAdmin,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']
    result = runBuyLicense(
        client, 'test1@testing.com', jwt=jwt,
        payload={'param': [
            {'eaType': 111, 'count': 3 }
        ]})
    verifyResponse(client, result, 200, 'buy-license')

    logResult = runGetUserLog(
        client, 'test1@testing.com', jwt=jwt,
        payload={'size': 32, 'startTime': 0, 'endTime': nowUnixEpochMS()})
    verifyResponseAndLog(result, logResult)

def test_buy_license_admin_multiple_type(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test admin create already exist user."""
    result = runAuth(client, payload={
        'userId': GlobalConfig.DbDefaultAdmin,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']
    result = runBuyLicense(
        client, 'test1@testing.com', jwt=jwt,
        payload={'param': [
            {'eaType': 111, 'count': 10, 'duration': 1 },
            {'eaType': 222, 'count': 20, 'duration': 2 },
            {'eaType': 333, 'count': 30, 'duration': 3 },
            {'eaType': 444, 'count': 40, 'duration': 4 },
            {'eaType': 555, 'count': 50 }
        ]})
    verifyResponse(client, result, 200, 'buy-license')
    assert len(result.json['result']) == 150, \
        'License count not match %d != %d' % (len(result.json['result']), 150)

    logResult = runGetUserLog(
        client, 'test1@testing.com', jwt=jwt,
        payload={'size': 32, 'startTime': 0, 'endTime': nowUnixEpochMS()})
    verifyResponseAndLog(result, logResult)

def test_buy_license_user_self(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test admin create already exist user."""
    result = runAuth(client, payload={
        'userId': 'test1@testing.com',
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']
    result = runBuyLicense(
        client, 'test1@testing.com', jwt=jwt,
        payload={'param': [
            {'eaType': 111, 'count': 3 }
        ]})
    verifyResponse(client, result, 403, 'buy-license')

def test_buy_license_user_other(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test admin create already exist user."""
    result = runAuth(client, payload={
        'userId': 'test1@testing.com',
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']
    result = runBuyLicense(
        client, 'test2@testing.com', jwt=jwt,
        payload={'param': [
            {'eaType': 111, 'count': 3 }
        ]})
    verifyResponse(client, result, 403, 'buy-license')

def test_buy_license_empty(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test admin create already exist user."""
    result = runAuth(client, payload={
        'userId': GlobalConfig.DbDefaultAdmin,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']
    result = runBuyLicense(
        client, 'test2@testing.com', jwt=jwt,
        payload={'param': []})
    verifyResponse(client, result, 200, 'buy-license')
    assert len(result.json['result']) == 0, \
        'License count not match %d != %d' % (len(result.json['result']), 0)
