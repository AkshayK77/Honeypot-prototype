import os
from datetime import timedelta

class Config:
    # Basic Flask Config
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(24)
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    WTF_CSRF_TIME_LIMIT = 3600
    WTF_CSRF_SSL_STRICT = True

    # Security Headers
    SECURITY_HEADERS = {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'SAMEORIGIN',
        'X-XSS-Protection': '1; mode=block',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' cdn.jsdelivr.net; img-src 'self' data:;"
    }

    # Redis Config for Rate Limiting
    REDIS_URL = os.environ.get('REDIS_URL') or 'redis://localhost:6379/0'

    # Email Configuration
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', True)
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER')

    # 2FA Configuration
    ENABLE_2FA = True
    TOTP_ISSUER = 'BruteForceSimulator'

    # Monitoring
    SENTRY_DSN = os.environ.get('SENTRY_DSN')
    ENABLE_PROMETHEUS = True

    # Password Policy
    PASSWORD_POLICY = {
        'MIN_LENGTH': 12,
        'REQUIRE_UPPERCASE': True,
        'REQUIRE_LOWERCASE': True,
        'REQUIRE_NUMBERS': True,
        'REQUIRE_SPECIAL': True,
        'MAX_AGE_DAYS': 90,
        'PREVENT_REUSE': 5  # Remember last 5 passwords
    }

    # Session Security
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    # API Rate Limiting
    API_RATE_LIMITS = {
        'DEFAULT': '100 per day',
        'LOGIN': '5 per minute',
        'REGISTER': '3 per hour',
        'RESET_PASSWORD': '3 per hour'
    }

class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///brute_force_sim.db'
    SESSION_COOKIE_SECURE = False  # Allow HTTP in development

class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
    ENABLE_2FA = False

class ProductionConfig(Config):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    ENABLE_PROMETHEUS = True
    
    # Production Security Settings
    SESSION_COOKIE_SECURE = True
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=15)  # Shorter session in production
    
    # Production Rate Limits
    API_RATE_LIMITS = {
        'DEFAULT': '1000 per day',
        'LOGIN': '5 per minute',
        'REGISTER': '10 per hour',
        'RESET_PASSWORD': '3 per hour'
    }

config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
} 