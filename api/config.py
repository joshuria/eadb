# -*- coding: utf-8 -*-
"""Global configuration retrieved from environment variable. """
import os
from datetime import timedelta


class GlobalConfig:
    """Global configuration holder.
    Variable list:
    + Server settings:
        * FLASK_DEBUG: defines whether app run in debug mode or not. Possible values are: ('1', '0').
            Default is '0'.
            Access variable: ServerDebug
        * FLASK_PORT: port number to bind.
            Default is '5000'.
            Access variable: ServerPort
    + DB settings:
        * DATABASE_NAME: name of all tables.
            Note that prefix must not contains '.'.
            Default is ''.
            Access variable: DbName
        * DATABASE_CONNNECTION_STRING: connection string of mongodb.
            Default is 'mongodb://localhost:27017'.
            Access variable: DbConnectionString
        * DATABASE_ADMIN_NAME: default admin user name.
            Suggest don't use admin or root.
            Default is ''
            Access variable DbDefaultAdmin
        * DATABASE_CREATE_INDEX_BACKGROUND: create index in background
            Default is true.
            Access variable DbCreateIndexInBackground
        * DATABASE_USER_LOG_EXPIRE_DAY: user operation log expire time in day.
            Default is 1 year (365 days).
            Access variable DbUserLogExpireDay
    + App settings:
        * USER_AGENT: acceptable user agent.
            Default is ""
            Access variable: AppUserAgent
        * API_KEYS: acceptable API keys. Format is ([a-z]|[A-Z]|[0-9])+{32}, separated by ','.
            Default is ""
            Access variable: AppApiKeys
        * JWT_SECRET: JWT secret key.
            Default is ""
            Access variable: JwtSecret
        * JWT_EXPIRE_SECONDS: JWT expire time in seconds.
            Default is "3600"
            Access variable: JwtExpireTime
    """
    # Server
    ServerDebug = os.getenv('FLASK_DEBUG', '0').lower() in ('true', 't', '1', 'y', 'yes')
    ServerPort = int(os.getenv('FLASK_PORT', '5000'))
    # DB
    DbName = os.getenv('DATABASE_NAME', '')
    DbConnectionString = os.getenv(
        'DATABASE_CONNECTION_STRING', 'mongodb://localhost:27017/' + DbName)
    DbDefaultAdmin = os.getenv('DATABASE_ADMIN_NAME', '')
    DbUserLogExpireDay = int(os.getenv('DATABASE_USER_LOG_EXPIRE_DAY', '365'))
    DbCreateIndexInBackground = os.getenv('DATABASE_CREATE_INDEX_BACKGROUND', '1').lower() in\
        ('true', 't', '1', 'y', 'yes')
    # App
    AppUserAgent = os.getenv('USER_AGENT', '')
    AppApiKeys = {
        x.strip() for x in os.getenv('API_KEYS', '').split(',')
    }
    JwtSecret = os.getenv('JWT_SECRET', '')
    JwtExpireTime = timedelta(seconds=int(os.getenv('JWT_EXPIRE_SECONDS', '3600')))
