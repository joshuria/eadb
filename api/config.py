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
        * DATABASE_ADMIN_HASHED_PASSWORD: default admin's hashed password.
            Default is ''.
            Access variable DbDefaultAdminPassword
        * DATABASE_CREATE_INDEX_BACKGROUND: create index in background
            Default is true.
            Access variable DbCreateIndexInBackground
        * DATABASE_USER_LOG_EXPIRE_DAY: user operation log expire time in day.
            Default is 1 year (365 days).
            Access variable DbUserLogExpireDay
        * DATABASE_USER_LICENSE_EXPIRE_DAY: activated license expire time in day.
            Default is 1 year (365 days).
            Access variable DbUserLicenseExpireDay
    + App settings:
        * USER_AGENT: acceptable user agent.
            Default is ""
            Access variable: AppUserAgent
        * API_ADMIN_KEY: admin API key. Format is ([a-z]|[A-Z]|[0-9])+{32}.
            Default is ""
            Access variable: ApiAdminKey
        * API_APP_KEY: App API key. Format is ([a-z]|[A-Z]|[0-9])+{32}.
            Default is ""
            Access variable: ApiAppKey
        * API_MAINTENANCE_KEY: maintenance key. Format is ([a-z]|[A-Z]|[0-9])+{32}
            Default is ""
            Access variable: ApiMaintenanceKey
        * JWT_SECRET: JWT secret key.
            Default is ""
            Access variable: JwtSecret
        * JWT_EXPIRE_SECONDS: JWT expire time in seconds.
            Default is "3600"
            Access variable: JwtExpireTime
        * APP_DEFAULT_DURATION_DAY: default license duration in day.
            Default is 30 days.
            Access variable: AppDefaultLicenseDurationDay
        * APP_MAX_QUERY_LICENSE_SIZE: max # of license ids to query at a time.
            Default is 32.
            Access variable: AppMaxQueryLicenseSize
    + Mail settings:
        * MAIL_SERVER: mail server domain name or IP.
            Default is 'localhost'.
            Access variable: MainServer
        * MAIL_SERVER_PORT: mail server port.
            Default is 587.
            Access variable: MainServerPort
        * MAIL_USERNAME: mail server user name.
            Default is "".
            Access variable: MailUsername
        * MAIL_PASSWORD: mail server password.
            Default is "".
            Access variable: MailPassword
        * MAIL_SENDER_ADDRESS: sender email address ot use.
            Default is "".
            Access variable: MailSenderAddress
    """
    # Server
    ServerDebug = os.getenv('FLASK_DEBUG', '0').lower() in ('true', 't', '1', 'y', 'yes')
    ServerPort = int(os.getenv('FLASK_PORT', '5000'))
    # DB
    DbName = os.getenv('DATABASE_NAME', '')
    DbConnectionString = os.getenv(
        'DATABASE_CONNECTION_STRING', 'mongodb://localhost:27017/' + DbName)
    DbDefaultAdmin = os.getenv('DATABASE_ADMIN_NAME', '')
    DbDefaultAdminPassword = os.getenv('DATABASE_ADMIN_HASHED_PASSWORD', '')
    DbUserLogExpireDay = int(os.getenv('DATABASE_USER_LOG_EXPIRE_DAY', '365'))
    DbCreateIndexInBackground = os.getenv('DATABASE_CREATE_INDEX_BACKGROUND', '1').lower() in\
        ('true', 't', '1', 'y', 'yes')
    DbUserLicenseExpireDay = int(os.getenv('DATABASE_USER_LICENSE_EXPIRE_DAY', '365'))
    # App
    AppUserAgent = os.getenv('USER_AGENT', '')
    ApiAdminKey = os.getenv('API_ADMIN_KEY', '')
    ApiAppKey = os.getenv('API_APP_KEY', '')
    ApiMaintenanceKey = os.getenv('API_MAINTENANCE_KEY', '')
    JwtSecret = os.getenv('JWT_SECRET', '')
    JwtExpireTime = timedelta(seconds=int(os.getenv('JWT_EXPIRE_SECONDS', '3600')))
    AppDefaultLicenseDurationDay = os.getenv('APP_DEFAULT_DURATION_DAY', 30)
    AppMaxQueryLicenseSize = os.getenv('APP_MAX_QUERY_LICENSE_SIZE', 32)

    MailServer = os.getenv('MAIL_SERVER', 'localhost')
    MailServerPort = int(os.getenv('MAIL_SERVER_PORT', '587'))
    MailUsername = os.getenv('MAIL_USERNAME', '')
    MailPassword = os.getenv('MAIL_PASSWORD', '')
    MailSenderAddress = os.getenv('MAIL_SENDER_ADDRESS', '')
