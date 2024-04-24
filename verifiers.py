import time

import jwt
from jwt import ExpiredSignatureError

import jwt_funcs


def verify_state(cache_code_verifier):
    if cache_code_verifier is None:
        raise ValueError('Incorrect state parameter! Possible tampering')


def verify_id_token(id_token, jwks_uri, exp_aud, exp_iss):
    header_data = jwt.get_unverified_header(id_token)

    # Find the JSON Web Key (JWK) corresponding to the key ID (kid) from the JWKS
    public_key = jwt_funcs.get_public_key(key_id=header_data['kid'], jwks_uri=jwks_uri)

    verify_jwt_signature_and_claims(id_token=id_token,
                                    public_key=public_key,
                                    jwt_alg=header_data['alg'],
                                    expected_audience=exp_aud,
                                    expected_issuer=exp_iss)


def verify_jwt_signature_and_claims(id_token, public_key, jwt_alg, expected_audience, expected_issuer):
    try:
        # Decode and verify the JWT signature, and validates optionally claims: audience, issuer
        # Remark: Verifying the JWT signature involves using the public key to verify that the token's signature
        # matches the contents of the header and payload
        decoded_token = jwt.decode(id_token, public_key, algorithms=[jwt_alg],
                                   audience=expected_audience, issuer=expected_issuer)

        # verify token is not expired
        verify_expiration(decoded_token['exp'])
        print("ID token verification successful!")

    except jwt.exceptions.InvalidTokenError as e:
        print("ID token verification failed:", e)


def verify_expiration(token_exp_time):
    current_time = time.time()
    if current_time >= token_exp_time:
        raise ExpiredSignatureError("Token has expired!")
