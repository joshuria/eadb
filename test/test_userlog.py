# -*- coding: utf-8 -*-
import flask, flask.testing
import pytest
from datetime import datetime
from api.config import GlobalConfig
from utility import DefaultPassword, addLog, runAuth, runGetUserLog, verifyResponse
from utility import createUser, removeUser


def setup_function() -> None:
    """Testing setup."""
    createUser('test1@testing.com', DefaultPassword)
    createUser('test2@testing.com', DefaultPassword)
    addLog('test1@testing.com', 1000)
    addLog('test2@testing.com', 1000)

def teardown_function() -> None:
    """Testing teardown."""
    removeUser('test1@testing.com')
    removeUser('test2@testing.com')

def test_get_log_no_auth_invalid_format(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test with no auth and invalid format."""
    timeRange = (datetime.utcnow().timestamp() * 1000, 0)
    size = 100
    result = runGetUserLog(client, 'nonono', '',
        payload={'size': size, 'startTime': timeRange[0], 'endTime': timeRange[1]})
    verifyResponse(client, result, 401, 'user-log')

def test_get_log_no_auth(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test with no auth."""
    timeRange = (datetime.utcnow().timestamp() * 1000, 0)
    size = 100
    result = runGetUserLog(client, 'test1@testing.com', '',
        payload={'size': size, 'startTime': timeRange[0], 'endTime': timeRange[1]})
    verifyResponse(client, result, 401, 'user-log')

def test_get_log_wrong_auth_header(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test invalid header."""
    timeRange = (datetime.utcnow().timestamp() * 1000, 0)
    size = 100
    result = runGetUserLog(
        client, 'nonono', 'fdj;fklasdjf9iopqwejfl;asdkfasdjf.werwqer.2282828',
        payload={'size': size, 'startTime': timeRange[0], 'endTime': timeRange[1]})
    verifyResponse(client, result, 401, 'user-log')

def test_get_log_missing_start_time(
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
    result = runGetUserLog(
        client, 'test1@testing.com', jwt=jwt,
        payload={'size': size, 'endTime': timeRange[1]})
    verifyResponse(client, result, 400, 'user-log')

def test_get_log_missing_all(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test missing parameter."""
    result = runAuth(client, payload={
        'userId': GlobalConfig.DbDefaultAdmin,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']
    result = runGetUserLog(client, 'test1@testing.com', jwt=jwt)
    verifyResponse(client, result, 400, 'user-log')

def test_get_log_admin(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test admin create already exist user."""
    result = runAuth(client, payload={
        'userId': GlobalConfig.DbDefaultAdmin,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']
    timeRange = ((datetime.utcnow().timestamp() - 3600 * 24 * 31) * 1000, 0)
    size = 100
    result = runGetUserLog(
        client, 'test1@testing.com', jwt=jwt,
        payload={'size': size, 'startTime': timeRange[0], 'endTime': timeRange[1]})
    verifyResponse(client, result, 200, 'user-log')
    assert len(result.json['result']) == size, '# return logs: %d' % (
        len(result.json['result']))
    data = result.json['result']
    assert all(data[i]['timestamp'] >= data[i+1]['timestamp'] for i in range(1,size-1)), \
        'Response log is not decreasing sorted.'

def test_get_log_self(
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
    result = runGetUserLog(
        client, 'test1@testing.com', jwt=jwt,
        payload={'size': size, 'startTime': timeRange[0], 'endTime': timeRange[1]})
    verifyResponse(client, result, 200, 'user-log')
    assert len(result.json['result']) == size, '# return logs: %d' % (
        len(result.json['result']))
    data = result.json['result']
    assert all(data[i]['timestamp'] >= data[i+1]['timestamp'] for i in range(1,size-1)), \
        'Response log is not decreasing sorted.'

def test_get_log_other(
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
    result = runGetUserLog(
        client, 'test2@testing.com', jwt=jwt,
        payload={'size': size, 'startTime': timeRange[0], 'endTime': timeRange[1]})
    verifyResponse(client, result, 403, 'user-log')

def test_get_log_self_loop(
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
    size = 100
    logs = []
    iteration = 0
    while True:
        print('Use range %f, %f' % (startTime, endTime))
        result = runGetUserLog(
            client, 'test1@testing.com', jwt=jwt,
            payload={'size': size, 'startTime': startTime, 'endTime': endTime})
        verifyResponse(client, result, 200, 'user-log')
        if len(result.json['result']) == 0:
            break
        assert len(result.json['result']) == result.json['remain']
        data = result.json['result']
        assert all(data[i]['timestamp'] >= data[i+1]['timestamp'] for i in range(1,len(data)-1)), \
            'Response log is not decreasing sorted.'
        assert all(
            (data[i]['timestamp'] >= startTime) and (data[i]['timestamp'] < endTime)
            for i in range(len(data))
        ), 'Return timestamp not in range'
        logs.extend(data)
        endTime = data[-1]['timestamp']-1
        iteration += 1
        if iteration > 50:
            assert False, 'Too many iteration'
    assert len(logs) == 1001, '# of retrived log not match: %d' % len(logs)
