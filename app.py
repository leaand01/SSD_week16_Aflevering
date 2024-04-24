from my_requests import AuthorizationAndIDToken, GetUserInfo
from flask import Flask, request, session
from flask_caching import Cache

import config
from pkce import Pkce
import endpoints
from redirecting import LocalRedirect, ExternalRedirect
from verifiers import verify_state, verify_id_token


app = Flask(__name__)
cache = Cache(app, config={'CACHE_TYPE': 'simple'})
app.secret_key = config.app_secret_key


@app.route('/')
def home():
    if 'username' in session:
        return f'You are now logged in with username: {session["username"]}'
    else:
        return 'landing page with login link <a href="/login">Login</a>'


@app.route('/login')
def login():
    pkce = Pkce()

    # cache code_verifier using a key-value-pair, using state as the key
    cache.set(config.state, pkce.code_verifier)

    return ExternalRedirect(parameters={"client_id": config.client_id,
                                        "scope": "openid email phone address profile",
                                        "response_type": "code",
                                        "redirect_uri": config.redirect_uri,
                                        "prompt": "login",
                                        "state": config.state,
                                        "code_challenge_method": pkce.code_challenge_method,
                                        "code_challenge": pkce.code_challenge
                                        }
                            ).to(endpoints.auth)


@app.route('/callback')
def callback():
    response_state = request.args.get('state')
    authorization_code = request.args.get('code')

    verify_state(cache_code_verifier=cache.get(response_state))

    # Resend code to get authorization and id token
    json_response = AuthorizationAndIDToken(parameters={"grant_type": "authorization_code",
                                                        "code": authorization_code,
                                                        "client_id": config.client_id,
                                                        "client_secret": config.client_secret,
                                                        "redirect_uri": config.redirect_uri,
                                                        "code_verifier": cache.get(response_state),
                                                        }
                                            ).send_request_to(endpoints.token)
    id_token = json_response['id_token']
    verify_id_token(id_token, endpoints.jwks_uri, exp_aud=config.client_id, exp_iss=endpoints.expected_issuer)

    # fetch userinfo
    userinfo_content = GetUserInfo(json_response['access_token']).send_request_to(endpoints.userinfo)

    # store userinfo in session
    session['username'] = userinfo_content['preferred_username']

    return LocalRedirect().to('/')


if __name__ == '__main__':
    app.run(debug=True)
