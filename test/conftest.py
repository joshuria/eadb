# -*- coding: utf-8 -*-
import os
import sys
import pytest

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
)


from app import create_app

@pytest.fixture(scope='session', autouse=True)
def client():
    """Testing client fixture."""
    app = create_app(True)
    testClient = app.test_client()
    cxt = app.app_context()
    cxt.push()
    yield testClient
    cxt.pop()
