# -*- coding: utf-8 -*-
"""Log model used in User model."""
import mongoengine as me
from ..timefunction import now


class Log(me.EmbeddedDocument):
    """Defines Log document used by User."""
    timestamp = me.DateTimeField(default=now)
    operation = me.IntField(required=True)
    ip = me.StringField(required=True)
    user = me.StringField(default='')

class LogOperation():
    """Defines tracked operations in log."""
    Login = 0x0
    CreateUser = 0x10
    DeleteUser = 0x11
    ModifyUser = 0x12
    LicenseBuy = 0x20
    LicenseActivate = 0x21
