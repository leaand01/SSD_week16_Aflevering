import urllib
from urllib.parse import urlencode
import hashlib
import base64
from secrets import token_urlsafe

import requests
from flask import Flask, redirect, request
from flask_caching import Cache
import jwt
import time

# import random
#
# random.seed(42)

client_id = 12345
# callback = 'http://127.0.0.1:5000/callback'
state = token_urlsafe(32)
code_verifier = token_urlsafe(32)
# hash
# sha256_hash = hashlib.sha256(code_verifier.encode()).digest()
# code_challenge = base64.urlsafe_b64encode(sha256_hash).decode()  # # Encode the hash in base64 URL-safe format
code_challenge = hashlib.sha256(code_verifier.encode()).hexdigest()
code_challenge_method = 'S256'

redirect_uri = 'http://127.0.0.1:5000/callback'


app = Flask(__name__)
cache = Cache(app, config={'CACHE_TYPE': 'simple'})

@app.route('/')
def home():
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
    # return redirect_url  #'Redirects to Keycloak'

@app.route('/callback')
def callback():
    print('request.args printed:')
    for key, value in request.args.items():
        print(f"{key}: {value}")

    state = request.args.get('state')
    code = request.args.get('code')
    # id_token = request.args.get('id_token')
    # refresh_token = request.args.get('refresh_token')
    # authorization_code = request.args.get('authorization_code')
    # client_secret_jwt = request.args.get('client_secret_jwt')
    # client_secret_basic = request.args.get('client_secret_basic')

    # verify state parameter
    # response_state = request.args.get('state')
    cache_code_verifier = cache.get(state)
    if cache_code_verifier is None:
        print('Incorrect state parameter! Possible tampering')
    else:
        print('state is correct.')

    # print('cached state and code_verifier:')
    # for key, value in cache.cache._cache.items():
    #     print(f"Key: {key}, Value: {value}")

    token_endpoint = 'http://localhost:8080/realms/master/protocol/openid-connect/token'
    # token_endpoint = 'http://localhost:8080/realms/master/protocol/openid-connect/auth'

    parameters = {
        "grant_type": "authorization_code",
        "code": code,  # authorization_code
        "client_id": client_id,
        "client_secret": 'rS83r63R3DtvQzETzMpxVqZWWvzzxmcH',  # copied from keycloak
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }
    # parameters = {
    #     "grant_type": "authorization_code",
    #     "code": code,  # authorization_code
    #     "redirect_uri": redirect_uri,
    #     # 'state': state,
    #     "code_verifier": code_verifier,
    #     "client_id": client_id,
    #     "client_secret": 'rS83r63R3DtvQzETzMpxVqZWWvzzxmcH'  # copied from keycloak
    # }

    # temp_url = f"{token_endpoint}?{urllib.parse.urlencode(parameters)}"
    # json_response = requests.post(temp_url).json()

    qs = urllib.parse.urlencode(parameters)
    json_response = requests.post(f"{token_endpoint}?{qs}", data=parameters).json()

    print('json_response')
    print(json_response)



    #
    # # verify id_token
    # response_id_token = request.args.get('id_token')
    # print(response_id_token)
    # print(type(response_id_token))
    # decoded_token = jwt.decode(id_token, algorithms=['RS256'])  #, options={"verify_signature": False}) # encode: convert to bytes format
    # expected_authorizer = 'http://localhost:8080/realms/master/protocol/openid-connect/auth'
    # expected_client_id = '12345'
    # if (decoded_token['iss'] != expected_authorizer
    #         or decoded_token['aud'] != expected_client_id
    #         or int(decoded_token['exp']) < time.time()):
    #     return 'Invalid ID token'
    #
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

    return 'Successful authorization between authorization server and client (my web-application)'


# http://127.0.0.1:5000/callback?state=6jRPqJXq4XoQxkmv6WUp-zHv4Eysh8qTEEGvWQS-AGU&session_state=5c212a15-5c1f-4bc0-891d-b11b3aef240e&code=7e78c441-7acd-4500-8cec-b36d26728421.5c212a15-5c1f-4bc0-891d-b11b3aef240e.3967dbdc-688c-4364-b630-6e3ac61c6f3e


if __name__ == '__main__':
    app.run(debug=True)
