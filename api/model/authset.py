# -*- coding: utf-8 -*-
"""Log model used in User model."""
from datetime import datetime
import mongoengine as me


class AuthSet(me.DynamicEmbeddedDocument):
    """Defines model of data for auth use."""
    jwt = me.StringField(default='')
    jwtTimestamp = me.DateTimeField(default=datetime.fromtimestamp(0))
