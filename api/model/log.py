# -*- coding: utf-8 -*-
"""Log model used in User model."""
from datetime import datetime
import mongoengine as me


class Log(me.EmbeddedDocument):
    """Defines Log document used by User."""
    timestamp = me.DateTimeField(default=datetime.utcnow())
    operation = me.IntField(required=True)
    ip = me.StringField(required=True)
    user = me.StringField(default='')

class LogOperation():
    """Defines tracked operations in log."""
    CreateUser = 0x10
    DeleteUser = 0x11
    ModifyUser = 0x12
    LicenseBuy = 0x20
    LicenseActivate = 0x21
