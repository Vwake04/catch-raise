import pytest
from main import app, configure_db_and_routes
from httpx import AsyncClient


@pytest.fixture(scope="session")
def anyio_backend():
    """
    Backend is asyncio by default.
    """
    return "asyncio"


@pytest.fixture(scope="session")
async def client():
    """
    Initialize test client.
    Set up test database.
    Configure routes.
    """
    test_db_name = "unittest_db"
    async with AsyncClient(app=app, base_url="http://test") as client:
        await configure_db_and_routes(db_name=test_db_name)

        print("Client initialized")

        yield client

        print("Client closed")

        from core.main import client

        await client.drop_database(test_db_name)
