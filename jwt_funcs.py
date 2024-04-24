import jwt
import requests


def get_public_key(key_id, jwks_uri):
    jwks = requests.get(jwks_uri).json()
    for key in jwks["keys"]:
        if key["kid"] == key_id:
            # create RSA public key object from the JWK representation
            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key)
            return public_key
    else:
        raise ValueError("Key not found for ID token.")
