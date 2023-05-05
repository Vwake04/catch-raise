"""
Main entry point of the application.
"""

from beanie import init_beanie
from motor.motor_asyncio import AsyncIOMotorClient
from fastapi_utils.tasks import repeat_every

from server import app

from datastore.init import init_import
from datastore.tasks.events import handle_events
from datastore.models import models as datastore_models
from datastore.routers import datastore_routers, include_routers

from settings import DEBUG, settings

client = AsyncIOMotorClient(settings.MASTER_DB_MONGO_URI)

async def init(client: AsyncIOMotorClient, db_name: str) -> None:
    """
    Initialize master database connection.
    """

    # Initialize beanie with the Product document class and a database
    await init_beanie(
        database=client[db_name],
        document_models=datastore_models,
        allow_index_dropping=True,
    )

    DEBUG and print("[+] Master database connection initialized.")


@app.on_event("startup")
async def configure_db_and_routes(db_name: str = settings.MASTER_DB_NAME) -> None:
    """
    Executed on application startup.
    """

    # Initialize database connection
    await init(client=client, db_name=db_name)
    await init_import()

    include_routers(
        app,
        routers=[
            datastore_routers,
        ]
    )


@app.on_event("startup")
@repeat_every(seconds=15 * 60, raise_exceptions=True)  # 15 minutes
async def remove_expired_tokens_task() -> None:
    print("[*] Chceking for latest vulnerabilities details")
    await handle_events()
    print("[*] Updating Completed")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=5000, reload=True, access_log=True)
