from backend.scanner.prowler_service import ProwlerService
from backend.scanner.parser import ASFFParser
from backend.core.config import settings

# Singleton instance
prowler_service_instance = ProwlerService(endpoint_url=settings.LOCALSTACK_ENDPOINT)


def get_prowler_service() -> ProwlerService:
    """Dependency provider for ProwlerService."""
    return prowler_service_instance


def get_parser() -> ASFFParser:
    """Dependency provider for ASFFParser."""
    return ASFFParser()
