# -*- coding: utf-8 -*-
"""EAStatus model used in User model."""
import mongoengine as me
from datetime import datetime


class EAStatus(me.EmbeddedDocument):
    """Defines EAStatus document used by User."""
    eaType = me.IntField(required=True)
    expiredTime = me.DateTimeField(default=datetime.fromtimestamp(0))
