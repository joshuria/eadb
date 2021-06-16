# -*- coding: utf-8 -*-
"""Log model used in User model."""
import mongoengine as me
from ..common import DefaultZeroDateTime


class AuthSet(me.DynamicEmbeddedDocument):
    """Defines model of data for auth use."""
    jwt = me.StringField(default='')
    jwtTimestamp = me.DateTimeField(default=DefaultZeroDateTime)
