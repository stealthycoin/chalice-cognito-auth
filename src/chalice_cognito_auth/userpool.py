import os

import boto3

from chalice_cognito_auth.blueprint import BlueprintFactory
from chalice_cognito_auth.decoder import TokenDecoder
from chalice_cognito_auth.decoder import KeyFetcher
from chalice_cognito_auth.authorizer import UserPoolAuthorizer
from chalice_cognito_auth.exceptions import ChallengeError


class UserPoolHandlerFactory:
    def __init__(self, blueprint_factory=None):
        if blueprint_factory is None:
            blueprint_factory = BlueprintFactory()
        self._blueprint_factory = blueprint_factory

    def create_user_pool_handler(self, app_client_id=None, user_pool_id=None,
                                 region=None, name=None):
        if app_client_id is None:
            app_client_id = os.environ.get('APP_CLIENT_ID')
        if user_pool_id is None:
            user_pool_id = os.environ.get('POOL_ID')
        if region is None:
            region = os.environ.get('AWS_REGION')
        if name is None:
            name = 'UserPoolAuth'
        key_fetcher = KeyFetcher(region, user_pool_id)
        decoder = TokenDecoder(key_fetcher, app_client_id)
        authorizer = UserPoolAuthorizer(decoder)
        cognito = boto3.client('cognito-idp', region_name=region)
        lifecycle = CognitoLifecycle(app_client_id, user_pool_id, cognito)
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

    @property
    def current_user(self):
        request = self.blueprint.current_request
        return request.context.get('authorizer', {}).get('principalId')

    @property
    def pid(self):
        return self.current_user


class CognitoLifecycle:
    def __init__(self, app_client_id, user_pool_id, cognito):
        self._app_client_id = app_client_id
        self._user_pool_id = user_pool_id
        self._cognito = cognito

    def _get_tokens(self, result):
        tokens = {}
        if 'IdToken' in result:
            tokens['id_token'] = result['IdToken']
        if 'RefreshToken' in result:
            tokens['refresh_token'] = result['RefreshToken']
        if 'AccessToken' in result:
            tokens['access_token'] = result['AccessToken']
        if 'TokenType' in result:
            tokens['token_type'] = result['TokenType']
        return tokens

    def _handle_auth_attempt(self, result):
        if 'ChallengeName' in result:
            raise ChallengeError(
	        result['ChallengeName'],
                result['Session'],
                result['ChallengeParameters'],
            )
        result = result['AuthenticationResult']
        if 'AccessToken' in result:
            return self._get_tokens(result)
        return result

    def register(self, username, password, properties):
        user_attributes = [
            {
                'Name': k,
                'Value': v,
            }
            for k, v in properties.items()
        ]
        result = self._cognito.sign_up(
            Username=username,
            Password=password,
            UserAttributes=user_attributes,
            ClientId=self._app_client_id,
        )

    def confirm(self, username, code):
        result = self._cognito.confirm_sign_up(
            ConfirmationCode=code,
            Username=username,
            ClientId=self._app_client_id,
        )
        return result

    def login(self, username, password):
        result = self._cognito.initiate_auth(
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password,
            },
            ClientId=self._app_client_id,
        )
        return self._handle_auth_attempt(result)

    def auth_challenge(self, challenge, session, params):
        result = self._cognito.respond_to_auth_challenge(
            ChallengeName=challenge,
            Session=session,
            ChallengeResponses=params,
            ClientId=self._app_client_id,
        )
        return self._handle_auth_attempt(result)

    def refresh(self, refresh_token):
        result = self._cognito.initiate_auth(
            AuthFlow='REFRESH_TOKEN_AUTH',
            AuthParameters={
                'REFRESH_TOKEN': refresh_token,
            },
            ClientId=self._app_client_id,
        )
        result = result['AuthenticationResult']
        if 'AccessToken' in result:
            return self._get_tokens(result)
        return result
