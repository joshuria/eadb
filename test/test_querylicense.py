# -*- coding: utf-8 -*-
import flask, flask.testing
import pytest
from datetime import datetime
from api.config import GlobalConfig
from utility import DefaultPassword, addLicense, runAuth, runQueryLicense, verifyResponse
from utility import createUser, removeUser


licenseList = []

def setup_function() -> None:
    """Testing setup."""
    createUser('test1@testing.com', DefaultPassword)
    createUser('test2@testing.com', DefaultPassword)
    licenseList.extend(addLicense('test1@testing.com', 200, 111, 30))
    licenseList.extend(addLicense('test1@testing.com', 100, 111, 30))
    addLicense('test2@testing.com', 10, 111, 30)

def teardown_function() -> None:
    """Testing teardown."""
    removeUser('test1@testing.com')
    removeUser('test2@testing.com')
    licenseList.clear()

def test_query_license_no_auth_invalid_format(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test with no auth and invalid format."""
    result = runQueryLicense(client, '')
    verifyResponse(client, result, 401, 'query-license')

def test_query_license_no_auth(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test with no auth."""
    size = 15
    lic = [l['lid'] for l in licenseList[:size]]
    result = runQueryLicense(client, '', payload={'param': lic})
    verifyResponse(client, result, 401, 'query-license')

def test_query_license_wrong_auth_header(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test invalid header."""
    size = 15
    lic = [l['lid'] for l in licenseList[:size]]
    result = runQueryLicense(
        client, 'fdj;fklasdjf9iopqwejfl;asdkfasdjf.werwqer.2282828',
        payload={'param': lic})
    verifyResponse(client, result, 401, 'query-license')

def test_query_license_admin(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test admin create already exist user."""
    result = runAuth(client, payload={
        'userId': GlobalConfig.DbDefaultAdmin,
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']
    size = 42
    lic = [l['lid'] for l in licenseList[:size]]
    result = runQueryLicense(client, jwt=jwt, payload={'param': lic})
    verifyResponse(client, result, 200, 'query-license')
    assert len(result.json['result']) == min(GlobalConfig.AppMaxQueryLicenseSize, size)

def test_query_license_self(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test admin create already exist user."""
    result = runAuth(client, payload={
        'userId': 'test1@testing.com',
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']
    size = 15
    lic = [l['lid'] for l in licenseList[:size]]
    result = runQueryLicense(client, jwt=jwt, payload={'param': lic})
    verifyResponse(client, result, 403, 'query-license')

def test_query_license_other(
    client: flask.testing.FlaskClient, capsys: pytest.CaptureFixture
) -> None:
    """Test admin create already exist user."""
    result = runAuth(client, payload={
        'userId': 'test1@testing.com',
        'password': DefaultPassword
    })
    verifyResponse(client, result, 200, 'auth')
    jwt = result.headers['JWT']
    size = 15
    lic = [l['lid'] for l in licenseList[:size]]
    result = runQueryLicense(client, jwt=jwt, payload={'param': lic})
    verifyResponse(client, result, 403, 'query-license')
