class VulnAgentError(Exception):
    """Base error for the scanner."""


class ValidationError(VulnAgentError):
    pass


class ScanNotFoundError(VulnAgentError):
    pass
