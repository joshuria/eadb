# -*- coding: utf-8 -*-
import flask, flask.testing
import pytest
from datetime import datetime
from api.config import GlobalConfig
from utility import DefaultPassword, addLicense, addLog, runAuth, runGetLicense, runGetUserLog, verifyResponse
from utility import createUser, removeUser


def setup_function() -> None:
    """Testing setup."""
    createUser('test1@testing.com', DefaultPassword)
    createUser('test2@testing.com', DefaultPassword)
    addLicense('test1@testing.com', 100, 111, 30)
    addLicense('test1@testing.com', 100, 111, 30)
    addLicense('test2@testing.com', 10, 111, 30)

def teardown_function() -> None:
    """Testing teardown."""
    removeUser('test1@testing.com')
    removeUser('test2@testing.com')

def test_get_license_no_auth_invalid_format(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test with no auth and invalid format."""
    timeRange = (datetime.utcnow().timestamp() * 1000, 0)
    size = 100
    result = runGetLicense(client, 'nonono', '',
        payload={'size': size, 'startTime': timeRange[0], 'endTime': timeRange[1]})
    verifyResponse(client, result, 401, 'get-license')

def test_get_license_no_auth(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test with no auth."""
    timeRange = (datetime.utcnow().timestamp() * 1000, 0)
    size = 100
    result = runGetLicense(client, 'test1@testing.com', '',
        payload={'size': size, 'startTime': timeRange[0], 'endTime': timeRange[1]})
    verifyResponse(client, result, 401, 'get-license')

def test_get_license_wrong_auth_header(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test invalid header."""
    timeRange = (datetime.utcnow().timestamp() * 1000, 0)
    size = 100
    result = runGetLicense(
        client, 'nonono', 'fdj;fklasdjf9iopqwejfl;asdkfasdjf.werwqer.2282828',
        payload={'size': size, 'startTime': timeRange[0], 'endTime': timeRange[1]})
    verifyResponse(client, result, 401, 'get-license')

def test_get_license_missing_start_time(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test missing parameter."""
    result = runAuth(client, payload={
        'userId': GlobalConfig.DbDefaultAdmin,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']
    timeRange = (datetime.utcnow().timestamp() * 1000, 0)
    size = 100
    result = runGetLicense(
        client, 'test1@testing.com', jwt=jwt,
        payload={'size': size, 'endTime': timeRange[1]})
    verifyResponse(client, result, 400, 'get-license')

def test_get_license_missing_all(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test missing parameter."""
    result = runAuth(client, payload={
        'userId': GlobalConfig.DbDefaultAdmin,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']
    result = runGetLicense(client, 'test1@testing.com', jwt=jwt)
    verifyResponse(client, result, 400, 'get-license')

def test_get_license_admin(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test admin create already exist user."""
    result = runAuth(client, payload={
        'userId': GlobalConfig.DbDefaultAdmin,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']
    timeRange = ((datetime.now().timestamp() - 3600 * 24 * 31) * 1000, datetime.now().timestamp() * 1000)
    print('Client range:', timeRange)
    size = 100
    result = runGetLicense(
        client, 'test1@testing.com', jwt=jwt,
        payload={'size': size, 'startTime': timeRange[0], 'endTime': timeRange[1]})
    verifyResponse(client, result, 200, 'get-license')
    assert len(result.json['result']) == size, '# return licenses: %d' % (
        len(result.json['result']))
    data = result.json['result']
    assert all((data[i]['buyTime'] >= timeRange[0]) and (data[i]['buyTime'] < timeRange[1])
        for i in range(1,size-1)), \
        'Response buyTime is not decreasing sorted.'

def test_get_license_self(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test admin create already exist user."""
    result = runAuth(client, payload={
        'userId': 'test1@testing.com',
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']
    timeRange = ((datetime.utcnow().timestamp() - 3600 * 24 * 31) * 1000, 0)
    size = 100
    result = runGetLicense(
        client, 'test1@testing.com', jwt=jwt,
        payload={'size': size, 'startTime': timeRange[0], 'endTime': timeRange[1]})
    verifyResponse(client, result, 200, 'get-license')
    #assert len(result.json['result']) == size, '# return logs: %d' % (
    #    len(result.json['result']))
    #data = result.json['result']
    #assert all(data[i]['timestamp'] >= data[i+1]['timestamp'] for i in range(1,size-1)), \
    #    'Response log is not decreasing sorted.'

def test_get_license_other(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test admin create already exist user."""
    result = runAuth(client, payload={
        'userId': 'test1@testing.com',
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']
    timeRange = (datetime.utcnow().timestamp() * 1000, 0)
    size = 100
    result = runGetLicense(
        client, 'test2@testing.com', jwt=jwt,
        payload={'size': size, 'startTime': timeRange[0], 'endTime': timeRange[1]})
    verifyResponse(client, result, 403, 'get-license')

def test_get_license_self_loop(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test admin create already exist user."""
    result = runAuth(client, payload={
        'userId': 'test1@testing.com',
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']
    startTime = 0
    endTime = datetime.now().timestamp() * 1000
    size = 10
    logs = []
    iteration = 0
    while True:
        print('Use range %f, %f' % (startTime, endTime))
        result = runGetLicense(
            client, 'test1@testing.com', jwt=jwt,
            payload={'size': size, 'startTime': startTime, 'endTime': endTime})
        verifyResponse(client, result, 200, 'get-license')
        if len(result.json['result']) == 0:
            break
        assert len(result.json['result']) == result.json['remain']
        data = result.json['result']
        assert all(data[i]['buyTime'] >= data[i+1]['buyTime'] for i in range(1,len(data)-1)), \
            'Response license is not decreasing sorted.'
        assert all(
            (data[i]['buyTime'] >= startTime) and (data[i]['buyTime'] < endTime)
            for i in range(len(data))
        ), 'Return buyTime not in range'
        logs.extend(data)
        endTime = data[-1]['buyTime']-1
        iteration += 1
        if iteration > 50:
            assert False, 'Too many iteration'
    assert len(logs) == 200, '# of retrived log not match: %d' % len(logs)
