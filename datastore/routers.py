"""
Configure routers for the application.
"""

from fastapi import FastAPI

from datastore.api import (
    cve_router, 
    cwe_router, 
    vendors_router, 
    products_router, 
    datastore_vulnerability_router
)


datastore_routers = [
    (cve_router, "/api"),
    (cwe_router, "/api"),
    (vendors_router, "/api"),
    (products_router, "/api"),
    (datastore_vulnerability_router, "/api/vulnerability"),
    
]


def include_routers(app: FastAPI, routers: list, dependencies: list = []):
    for router in routers:
        for route, prefix in router:
            app.include_router(
                route,
                prefix=prefix,
                dependencies=dependencies,
            )
    return app
