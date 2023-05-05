"""
Settings for development environment.
"""

from pydantic import BaseSettings
from decouple import config


class Settings(BaseSettings):
    """
    Settings for development environment.
    """

    # Application settings
    APP_NAME: str = "Datastore"
    APP_DESCRIPTION: str = "Vulnerability Datastore"
    APP_VERSION: str = "0.1.0"
    APP_ENV: str = "development"

    # Database settings
    MASTER_DB_MONGO_URI: str = config("MASTER_DB_MONGO_URI")
    MASTER_DB_NAME: str = config("MASTER_DB_NAME")

    # Server settings
    SERVER_HOST: str = "0.0.0.0"