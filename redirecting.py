import urllib
from abc import ABC, abstractmethod

from flask import redirect


class Redirecting(ABC):
    @abstractmethod
    def to(self, endpoint):
        pass


class ExternalRedirect(Redirecting):
    """Redirecting to external endpoint like Keycloak."""
    def __init__(self, parameters):
        self.parameters = parameters

    def to(self, endpoint):
        redirect_url = f"{endpoint}?{urllib.parse.urlencode(self.parameters)}"
        return redirect(redirect_url)


class LocalRedirect(Redirecting):
    """Redirecting to endpoint in app."""
    def to(self, endpoint):
        return redirect(endpoint)
