import urllib
from urllib.parse import urlencode
import hashlib
import base64
from secrets import token_urlsafe, token_hex

import requests
from flask import Flask, redirect, request, session
from flask_caching import Cache
import jwt
import time
from jwt.exceptions import ExpiredSignatureError


def create_challenge(code_verifier: str) -> str:
   code_challenge = hashlib.sha256(code_verifier.encode()).digest()
   encoded_challenge = base64.urlsafe_b64encode(code_challenge).decode().replace('=', '')
   return encoded_challenge


client_id = 12345
state = token_urlsafe(32)
code_verifier = token_urlsafe(32)
code_challenge_method = 'S256'
code_challenge = create_challenge(code_verifier)
redirect_uri = 'http://127.0.0.1:5000/callback'


app = Flask(__name__)
cache = Cache(app, config={'CACHE_TYPE': 'simple'})
app.secret_key = token_hex(32)

@app.route('/')
def home():
    if 'username' in session:
        return f'You are now logged in with username: {session["username"]}'
    else:
        return 'landing page with login link <a href="/login">Login</a>'

@app.route('/login')
def login():
    authorization_endpoint = 'http://localhost:8080/realms/master/protocol/openid-connect/auth'

    parameters = {
        "client_id": client_id,
        "scope": "openid email phone address profile",
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "prompt": "login",
        "state": state,
        "code_challenge_method": code_challenge_method,
        "code_challenge": code_challenge  #create_challenge(code_verifier)
    }
    redirect_url = f"{authorization_endpoint}?{urllib.parse.urlencode(parameters)}"

    # cache
    cache.set(state, code_verifier)  # cache code_verifier using a key-value-pair, where state is the key
    return redirect(redirect_url)

@app.route('/callback')
def callback():
    # print('request.args printed:')
    # for key, value in request.args.items():
    #     print(f"{key}: {value}")

    state = request.args.get('state')
    code = request.args.get('code')

    # verify state parameter
    cache_code_verifier = cache.get(state)
    if cache_code_verifier is None:
        print('Incorrect state parameter! Possible tampering')
    else:
        print('state is correct.')

    # resend code to get authorization and id token
    token_endpoint = 'http://localhost:8080/realms/master/protocol/openid-connect/token'
    parameters = {
        "grant_type": "authorization_code",
        "code": code,  # authorization_code
        "client_id": client_id,
        "client_secret": 'rS83r63R3DtvQzETzMpxVqZWWvzzxmcH',  # copied from keycloak
        "redirect_uri": redirect_uri,
        "code_verifier": cache_code_verifier,
    }
    qs = urllib.parse.urlencode(parameters)
    json_response = requests.post(f"{token_endpoint}?{qs}", data=parameters).json()
    #
    # print('json_response')
    # print(json_response)

    # verify the returned ID token
    # use PyJWT to verify ID Token.
    id_token = json_response['id_token']
    client_secret = 'rS83r63R3DtvQzETzMpxVqZWWvzzxmcH' # copied from keycload

    header_data = jwt.get_unverified_header(id_token)
    algorithm = header_data['alg']
    header_key = header_data['kid']
    id_token_payload = jwt.decode(id_token, client_secret, algorithms=[algorithm], options={"verify_signature": False})
    # id_token_payload = jwt.decode(id_token, client_secret, algorithms=[header_data['alg']], options={"verify_signature": False})
    # print('id_token_payload: ', id_token_payload)




    # Find the JSON Web Key (JWK) corresponding to the key ID (kid) from the JWKS
    jwks_uri = 'http://localhost:8080/realms/master/protocol/openid-connect/certs'
    response = requests.get(jwks_uri)
    jwks = response.json()

    for key in jwks["keys"]:
        if key["kid"] == header_key:
            print('\n\ntesting printing key:', key)
            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key)  # create RSA public key object from the JWK representation
            break
    else:
        raise ValueError("Key not found for ID token.")

    excpected_audience = '12345'
    expected_issuer = 'http://localhost:8080/realms/master'
    # Verify the ID token signature using the public key (verified if can decode using the public key)
    try:
        # decodes and verifies the JWT signature, validates optionally claims: audience, issuer
        decoded_token = jwt.decode(id_token, public_key, algorithms=[algorithm], audience=excpected_audience, issuer=expected_issuer)
        # By providing the additional parameters audience and issuer to the jwt.decode() function, PyJWT will
        # # automatically validate the token's claims against the specified values
        # decoded_token = jwt.decode(id_token, public_key, algorithms=[algorithm], audience="12345", issuer='http://localhost:8080/realms/master')

        # verify token is not expired
        current_time = time.time()
        if current_time >= decoded_token['exp']:
            raise ExpiredSignatureError("Token has expired!")

        print("ID token verification successful!")
        print(decoded_token)
        # Verifying the JWT signature involves using the public key to verify that the token's signature matches the contents of the header and payloa
    except jwt.exceptions.InvalidTokenError as e:
        print("ID token verification failed:", e)


    # fetch user info
    userinfo_endpoint = 'http://localhost:8080/realms/master/protocol/openid-connect/userinfo'
    headers = {"Authorization": f"Bearer {json_response['access_token']}"}
    content = requests.get(userinfo_endpoint, headers=headers).json()
    print('content: ', content)

    # print('\n når vi hertil?')
    # store userinfo in session
    session['username'] = content['preferred_username']

    return redirect('/')








    # keys in json_response:
    # access_token
    # expires_in
    # refresh_expires_in
    # refresh_token
    # token_type
    # id_token
    # session_state
    # scope


    # verify id_token
    # id_token = json_response['id_token']
    # id_token = 'eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJkOVpQR2ZrUVZFMGVjM1o4Wl9HdmQxNHV2Yy1wdGNjMkR4aFZ1MXhIazdRIn0.eyJleHAiOjE3MTM4NjgyNzQsImlhdCI6MTcxMzg2ODIxNCwiYXV0aF90aW1lIjoxNzEzODY4MjE0LCJqdGkiOiJiNGU1ZmY4Yy01Yjk4LTQ3Y2UtOTI0Zi1mMjI2MmNkMGMxYmYiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvcmVhbG1zL21hc3RlciIsImF1ZCI6IjEyMzQ1Iiwic3ViIjoiN2ViM2VhZGYtZDI0OC00MmY2LTllOGQtNWQwNzdhZWEwN2MzIiwidHlwIjoiSUQiLCJhenAiOiIxMjM0NSIsInNlc3Npb25fc3RhdGUiOiJjMWVlNjkwNy1mNDYyLTRiODgtYTMyZS0xYWY3Mzk3MTQxM2YiLCJhdF9oYXNoIjoiUXdBRWZidjFSTVRULWM5SmJfaVNZdyIsImFjciI6IjEiLCJzaWQiOiJjMWVlNjkwNy1mNDYyLTRiODgtYTMyZS0xYWY3Mzk3MTQxM2YiLCJhZGRyZXNzIjp7fSwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhZG1pbiJ9.SMuuGDRSxVKGzePrn6Z4EUi_v9S6NjbJBhnpcYZNv6sEW7m-c0N2YJoMa2q61R5hGG7fuaQB8A611lp1iYsE8m1vU6r6s99jDLNGBPp_3IPwcsOrl7BSUHUdPeJlieWWxn5HgMGPOQG_niuB548GuXoyLWCrF0v2b20rmCF113tXwM4Z96NeM5kRdwwSvVSUPF8cIs_a3JzBd5NCmYY5bKamKUfRKms2lBbQOY6267eHJ-BW59ZTX-nRKFQ_93E0PzPPx-mvuKs4hPSHy4pe-2avkP4ErB5YYBJTQWJhIv7XkstA5ug1hWMKsKv4OWgE7zVW_CgHmf5-2Z7qpkVNJw'
    # # algorithm = jwt.get_unverified_header(id_token).get('alg')
    # # a = jwt.decode(token=id_token, key=json_response, algorithms=algorithm)
    # # a = jwt.decode(jwt=id_token, key=json_response, algorithms='RS256')
    # a = jwt.decode(jwt=id_token, key='d9ZPGfkQVE0ec3Z8Z_Gvd14uvc-ptcc2DxhVu1xHk7Q', algorithms=['RS256'])
    # print('a:', a)



    # decoded_token = jwt.decode(jwt=id_token, key='secret', algorithms=['HS256'])  # , options={"verify_signature": False}) # encode: convert to bytes format
    #
    # response_id_token = request.args.get('id_token')
    # decoded_token = jwt.decode(id_token, algorithms=['RS256'])  #, options={"verify_signature": False}) # encode: convert to bytes format
    # expected_authorizer = 'http://localhost:8080/realms/master/protocol/openid-connect/auth'
    # expected_client_id = '12345'
    # if (decoded_token['iss'] != expected_authorizer
    #         or decoded_token['aud'] != expected_client_id
    #         or int(decoded_token['exp']) < time.time()):
    #     return 'Invalid ID token'

    # token_endpoint = 'http://localhost:8080/realms/master/protocol/openid-connect/token'
    # parameters = {
    #     "grant_type": "authorization_code",
    #     "code": authorization_code,
    #     "redirect_uri": 'http://127.0.0.1:5000/callback',  #redirect_uri,
    #     "code_verifier": code_verifier,
    #     "client_id": client_id,
    #     "client_secret": client_secret_basic
    # }
    # qs = urllib.parse.urlencode(parameters)
    # json_response = requests.post(f"{token_endpoint}?{qs}", data=parameters).json()
    #
    # print(json_response)
    # access_token = request.args.get('access_token')
    # userinfo_endpoint = 'http://localhost:8080/realms/master/protocol/openid-connect/userinfo'
    #
    # headers = {"Authorization": f"Bearer {access_token}"}
    # content = requests.get(userinfo_endpoint, headers=headers).json()
    # print(content)

    # return 'Successful authorization between authorization server and client (my web-application)'


# http://127.0.0.1:5000/callback?state=6jRPqJXq4XoQxkmv6WUp-zHv4Eysh8qTEEGvWQS-AGU&session_state=5c212a15-5c1f-4bc0-891d-b11b3aef240e&code=7e78c441-7acd-4500-8cec-b36d26728421.5c212a15-5c1f-4bc0-891d-b11b3aef240e.3967dbdc-688c-4364-b630-6e3ac61c6f3e


if __name__ == '__main__':
    app.run(debug=True)
