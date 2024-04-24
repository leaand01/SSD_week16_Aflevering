import urllib.parse
from abc import ABC, abstractmethod

import requests


class MyRequest(ABC):
    @abstractmethod
    def send_request_to(self, endpoint):
        pass


class AuthorizationAndIDToken(MyRequest):
    """Resend code to get authorization and id token."""

    def __init__(self, parameters):
        self.parameters = parameters

    def send_request_to(self, endpoint):
        qs = urllib.parse.urlencode(self.parameters)
        return requests.post(f"{endpoint}?{qs}", data=self.parameters).json()


class GetUserInfo(MyRequest):
    """Fetch user info."""

    def __init__(self, access_token):
        self.access_token = access_token

    def send_request_to(self, endpoint):
        headers = {"Authorization": f"Bearer {self.access_token}"}
        content = requests.get(endpoint, headers=headers).json()
        print('content: ', content)
        return content
