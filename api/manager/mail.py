# -*- coding: utf-8 -*-
"""Mail sending manager."""
from flask_mail import Mail, Message
from ..config import GlobalConfig


class MailManager:
    """Singleton Mail manager."""
    mail = Mail()

    @staticmethod
    def initialize(app) -> None:
        """Initialize manager with flask app intance."""
        MailManager.mail.init_app(app)

    @staticmethod
    def sendMail(address: str, title: str, body: str) -> None:
        """Send mail to user. """
        msg = Message(title, sender=GlobalConfig.MailSenderAddress, recipients=[address])
        msg.body = body
        MailManager.mail.send(msg)
