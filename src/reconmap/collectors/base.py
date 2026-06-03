from abc import ABC, abstractmethod

from reconmap.models.asset import AssetSnapshot


class BaseCollector(ABC):
    name: str = ""
    requires_key: bool = False

    @abstractmethod
    async def collect(self, domain: str) -> AssetSnapshot:
        """Collect passive recon data for domain. Return partial AssetSnapshot."""
        ...

    def is_available(self) -> bool:
        """Return False if requires_key=True and key not configured."""
        return True
