from datastore.models.base import BaseDocument


class Metas(BaseDocument):
    name: str
    value: str

    def __str__(self):
        return f"<Meta {self.name}>"

    def __repr__(self):
        return f"<Meta {self.name}>"

    class Settings:
        name = "metas"