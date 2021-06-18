# -*- coding: utf-8 -*-
"""Log model used in User model."""
from datetime import datetime
import mongoengine as me


class License(me.EmbeddedDocument):
    """Defines model of license collection used by User collection."""
    lid = me.StringField(db_field='_id', primary_key=True)
    eaType = me.IntField(required=True)
    durationDay = me.IntField(db_field='duration', default=30)
    owner = me.StringField(required=True)
    buyTime = me.DateTimeField(default=datetime.utcnow())
    consumer = me.StringField(default='')
    activationTime = me.DateTimeField(default=datetime.fromtimestamp(0))
    activationIp = me.StringField(default='')
