# -*- coding: utf-8 -*-
"""ProductStatus model used in User model."""
import mongoengine as me
from ..timefunction import ZeroDateTime


class ProductStatus(me.EmbeddedDocument):
    """Defines product status document used by User."""
    broker = me.StringField(required=True)
    eaId = me.StringField(required=True)
    mId = me.StringField(required=True)
    expireTime = me.DateTimeField(default=ZeroDateTime)
