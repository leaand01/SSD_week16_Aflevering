from secrets import token_urlsafe, token_hex

client_id = '12345'
client_secret = 'rS83r63R3DtvQzETzMpxVqZWWvzzxmcH'  # copied from keycloak
state = token_urlsafe(32)

redirect_uri = 'http://127.0.0.1:5000/callback'

app_secret_key = token_hex(32)