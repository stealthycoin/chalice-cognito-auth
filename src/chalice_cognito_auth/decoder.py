import time
import json
import urllib.request

from jose import jwt
from jose import jwk
from jose.utils import base64url_decode

from chalice_cognito_auth.exceptions import InvalidToken
from chalice_cognito_auth.utils import env_var
from chalice_cognito_auth.constants import REGION_ENV_VAR
from chalice_cognito_auth.constants import USER_POOL_ID_ENV_VAR
from chalice_cognito_auth.constants import CLIENT_ID_ENV_VAR


class TokenDecoder:
    def __init__(self, key_fetcher, app_client_id, now=None):
        self._key_fetcher = key_fetcher
        self._app_client_id = app_client_id
        if now is None:
            now = time.time
        self._now = now

    @classmethod
    def from_env(cls) -> 'TokenDecoder':
        return cls(
            key_fetcher=KeyFetcher.from_env(),
            app_client_id=env_var(CLIENT_ID_ENV_VAR),
        )

    def decode(self, token):
        try:
            self._verify(token)
            claims = self._get_claims(token)
            return claims
        except InvalidToken:
            raise
        except Exception:
            raise InvalidToken('Error decoding token')

    def _verify(self, token):
        headers = jwt.get_unverified_headers(token)
        kid = headers['kid']
        key = self._get_key(kid)
        public_key = jwk.construct(key)
        message, encoded_signature = str(token).rsplit('.', 1)
        decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))
        if not public_key.verify(message.encode("utf8"), decoded_signature):
            raise InvalidToken('Signature verification failed')

    def _get_key(self, kid):
        for key in self._key_fetcher.get_keys():
            if key['kid'] == kid:
                return key
        raise InvalidToken('Could not find kid %s' % kid)

    def _get_claims(self, token):
        claims = jwt.get_unverified_claims(token)
        if self._now() > claims['exp']:
            raise InvalidToken('Token expired')
        if claims['aud'] != self._app_client_id:
            raise InvalidToken('Token was not issued for this audience')
        return claims


class KeyFetcher:
    _KEYS_URL = (
        'https://cognito-idp.{region}.amazonaws.com'
        '/{user_pool_id}/.well-known/jwks.json'
    )

    def __init__(self, region, user_pool_id, urlopen=None):
        self._region = region
        self._user_pool_id = user_pool_id
        self._keys = None
        if urlopen is None:
            urlopen = urllib.request.urlopen
        self._urlopen = urlopen

    @classmethod
    def from_env(cls) -> 'KeyFetcher':
        return cls(
            region=env_var(REGION_ENV_VAR),
            user_pool_id=env_var(USER_POOL_ID_ENV_VAR),
        )

    def get_keys(self):
        if self._keys is None:
            self._keys = self._get_keys()
        return self._keys

    def _get_keys(self):
        url = self._KEYS_URL.format(
            region=self._region,
            user_pool_id=self._user_pool_id,
        )
        return json.loads(self._urlopen(url).read())['keys']
