# -*- coding: utf-8 -*-
"""EAStatus model used in User model."""
import mongoengine as me
from ..timefunction import ZeroDateTime


class EAStatus(me.EmbeddedDocument):
    """Defines EAStatus document used by User."""
    eaType = me.IntField(required=True)
    expiredTime = me.DateTimeField(default=ZeroDateTime)
