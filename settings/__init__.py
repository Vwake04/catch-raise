from decouple import config

if config("APP_ENV") == "dev":
    from .development import Settings
    settings = Settings()

DEBUG = config("DEBUG", default=True, cast=bool)
