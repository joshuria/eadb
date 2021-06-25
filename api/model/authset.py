# -*- coding: utf-8 -*-
"""Log model used in User model."""
import mongoengine as me
from ..timefunction import ZeroDateTime


class AuthSet(me.DynamicEmbeddedDocument):
    """Defines model of data for auth use."""
