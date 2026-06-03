import json
from reconmap.models.asset import AssetSnapshot, Change


class JSONReporter:
    def generate(self, snapshot: AssetSnapshot) -> dict:
        return snapshot.model_dump(mode="json")

    def generate_changes(self, changes: list[Change]) -> list[dict]:
        return [c.model_dump(mode="json") for c in changes]

    def write(self, snapshot: AssetSnapshot, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.generate(snapshot), fh, indent=2)

    def write_changes(self, changes: list[Change], path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.generate_changes(changes), fh, indent=2)
