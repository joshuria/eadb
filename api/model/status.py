# -*- coding: utf-8 -*-
"""Defines account status."""


class Status():
    """User account status enum."""
    Disabled = 0
    Enabled = 1

    @staticmethod
    def getAllStatus():
        """Get all supported status."""
        return (Status.Disabled, Status.Enabled)
