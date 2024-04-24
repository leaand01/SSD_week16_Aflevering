import base64
import hashlib
from dataclasses import dataclass
from secrets import token_urlsafe


@dataclass
class Pkce:
    code_verifier: str = token_urlsafe(32)
    code_challenge_method: str = 'S256'

    def __post_init__(self):
        self.code_challenge = self.create_challenge()

    def create_challenge(self) -> str:
        code_challenge = hashlib.sha256(self.code_verifier.encode()).digest()
        encoded_challenge = base64.urlsafe_b64encode(code_challenge).decode().replace('=', '')
        return encoded_challenge
