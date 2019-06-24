import os

from warrant import Cognito

from chalice_cognito_auth.blueprint import BlueprintFactory
from chalice_cognito_auth.decoder import TokenDecoder
from chalice_cognito_auth.decoder import KeyFetcher
from chalice_cognito_auth.authorizer import UserPoolAuthorizer


class UserPoolHandlerFactory:
    def __init__(self, blueprint_factory=None):
        if blueprint_factory is None:
            blueprint_factory = BlueprintFactory()
        self._blueprint_factory = blueprint_factory

    def create_user_pool_handler(self, app_client_id=None, user_pool_id=None,
                                 region=None, name=None):
        if app_client_id is None:
            app_client_id = os.environ.get('CLIENT_APP_ID')
        if user_pool_id is None:
            user_pool_id = os.environ.get('POOL_ID')
        if region is None:
            region = os.environ.get('AWS_REGION')
        if name is None:
            name = 'UserPoolAuth'
        key_fetcher = KeyFetcher(region, user_pool_id)
        decoder = TokenDecoder(key_fetcher, app_client_id)
        authorizer = UserPoolAuthorizer(decoder)
        lifecycle = CognitoLifecycle(app_client_id, user_pool_id)
        blueprint, auth_wrapper = self._blueprint_factory.create_blueprint(
            name, authorizer, lifecycle)
        handler = UserPoolHandler(authorizer, blueprint, auth_wrapper)
        return handler


class UserPoolHandler:
    def __init__(self, authorizer, blueprint, auth_wrapper):
        self._authorizer = authorizer
        self.blueprint = blueprint
        self._auth_wrapper = auth_wrapper

    @property
    def auth(self):
        return self._auth_wrapper


class CognitoLifecycle:
    def __init__(self, app_client_id, user_pool_id, cognito=None):
        self._app_client_id = app_client_id
        self._user_pool_id = user_pool_id
        if cognito is None:
            cognito = Cognito
        self._cognito = cognito

    def _get_tokens(self, u):
        tokens = {}
        if hasattr(u, 'id_token') and u.id_token is not None:
            tokens['id_token'] = u.id_token
        if hasattr(u, 'refresh_token') and u.refresh_token is not None:
            tokens['refresh_token'] = u.refresh_token
        if hasattr(u, 'access_token') and u.access_token is not None:
            tokens['access_token'] = u.access_token
        if hasattr(u, 'token_type') and u.token_type is not None:
            tokens['token_type'] = u.token_type
        return tokens

    def login(self, username, password):
        u = self._cognito(
            self._user_pool_id,
            self._app_client_id,
            username=username,
        )
        u.authenticate(password=password)
        return self._get_tokens(u)


    def refresh(self, id_token, refresh_token, access_token):
        u = self._cognito(
            self._user_pool_id,
            self._app_client_id,
            id_token=id_token,
            refresh_token=refresh_token,
            access_token=access_token,
        )
        u.check_token()
        return self._get_tokens(u)

    def logout(self, access_token):
        u = self._cognito(
            self._user_pool_id,
            self._app_client_id,
            access_token=access_token,
        )
        u.logout()
