# -*- coding: utf-8 -*-
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
)

import pytest
from app import create_app
from api.config import GlobalConfig

@pytest.fixture
def client():
    app = create_app(True)
    client = app.test_client()
    cxt = app.app_context()
    cxt.push()
    yield client
    cxt.pop()
