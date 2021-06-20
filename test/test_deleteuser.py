# -*- coding: utf-8 -*-
import flask, flask.testing
import pytest
from api.config import GlobalConfig
from utility import DefaultPassword, runAuth, runDeleteUser, runGetUser, verifyResponse
from utility import createUser, removeUser


def setup_function() -> None:
    """Testing setup."""
    createUser('test1@testing.com', DefaultPassword)
    createUser('test2@testing.com', DefaultPassword)

def teardown_function() -> None:
    """Testing teardown."""
    removeUser('test1@testing.com')
    removeUser('test2@testing.com')

def test_delete_user_no_auth_invalid_format(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test with no auth and invalid format."""
    result = runDeleteUser(client, 'nonono', '')
    verifyResponse(client, result, 401, 'delete')

def test_delete_user_no_auth(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test with no auth."""
    result = runDeleteUser(client, 'test1@testing.com', '')
    verifyResponse(client, result, 401, 'delete')

def test_delete_user_wrong_auth_header(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test invalid header."""
    result = runDeleteUser(
        client, 'nonono', 'fdj;fklasdjf9iopqwejfl;asdkfasdjf.werwqer.2282828')
    verifyResponse(client, result, 401, 'delete')

def test_delete_by_admin(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test admin create normal user."""
    result = runAuth(client, payload={
        'userId': GlobalConfig.DbDefaultAdmin,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']
    result = runDeleteUser(client, 'test2@testing.com', jwt=jwt)
    verifyResponse(client, result, 200, 'delete')
    result = runGetUser(client, 'test2@testing.com', jwt=jwt)
    verifyResponse(client, result, 404, 'getuser')
    result = runAuth(client, 'test2@testing.com')
    verifyResponse(client, result, 404, 'auth')

def test_delete_by_self(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test admin create normal user."""
    result = runAuth(client, payload={
        'userId': 'test1@testing.com',
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']
    result = runDeleteUser(client, 'test1@testing.com', jwt=jwt)
    verifyResponse(client, result, 403, 'delete')
    result = runGetUser(client, 'test1@testing.com', jwt=jwt)
    verifyResponse(client, result, 200, 'getuser')

def test_delete_user_not_exist(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test admin create already exist user."""
    result = runAuth(client, payload={
        'userId': GlobalConfig.DbDefaultAdmin,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']
    result = runDeleteUser(client, 'nonono@testing.com', jwt=jwt)
    verifyResponse(client, result, 404, 'delete')
    result = runGetUser(client, 'nonono@testing.com', jwt=jwt)
    verifyResponse(client, result, 404, 'getuser')
