# -*- coding: utf-8 -*-
import flask, flask.testing
import pytest
from api.config import GlobalConfig
from utility import DefaultPassword, runAuth, runCreateUser, verifyResponse
from utility import createUser, removeUser


def setup_function() -> None:
    """Testing setup."""
    createUser('test1@testing.com', DefaultPassword)

def teardown_function() -> None:
    """Testing teardown."""
    removeUser('test1@testing.com')
    removeUser('test2@testing.com')

def test_create_user_no_auth_invalid_format(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test with no auth and invalid format."""
    result = runCreateUser(client, 'nonono', '', payload={
            'password': 'xxxxx'
        })
    verifyResponse(client, result, 401, 'create')

def test_create_user_no_auth(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test with no auth."""
    result = runCreateUser(client, 'nonono@testing.com', '', payload={
            'password': 'xxxxx'
        })
    verifyResponse(client, result, 401, 'create')

def test_create_user_wrong_auth_header(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test invalid header."""
    result = runCreateUser(
        client, 'nonono', 'fdj;fklasdjf9iopqwejfl;asdkfasdjf.werwqer.2282828',
        payload={'password': DefaultPassword})
    verifyResponse(client, result, 401, 'create')

def test_create_user_correct(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test admin create normal user."""
    result = runAuth(client, payload={
        'userId': GlobalConfig.DbDefaultAdmin,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    result = runCreateUser(
        client, 'test2@testing.com', jwt=result.headers['JWT'],
        payload={'password': DefaultPassword})
    verifyResponse(client, result, 200, 'create')

def test_create_user_non_admin(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test normal user create user."""
    result = runAuth(client, payload={
        'userId': 'test1@testing.com',
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    result = runCreateUser(
        client, 'test2@testing.com', jwt=result.headers['JWT'],
        payload={'userId': 'test-user1@testing.com', 'password': DefaultPassword})
    verifyResponse(client, result, 403, 'create')

def test_create_user_exist(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test admin create already exist user."""
    result = runAuth(client, payload={
        'userId': GlobalConfig.DbDefaultAdmin,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    result = runCreateUser(
        client, 'test-user@testing.com', jwt=result.headers['JWT'],
        payload={
            'userId': 'test1@testing.com',
            'password': DefaultPassword
        })
    verifyResponse(client, result, 409, 'create')
