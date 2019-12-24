import boto3

from chalice_cognito_auth.blueprint import BlueprintFactory
from chalice_cognito_auth.decoder import TokenDecoder
from chalice_cognito_auth.decoder import KeyFetcher
from chalice_cognito_auth.authorizer import UserPoolAuthorizer
from chalice_cognito_auth.exceptions import ChallengeError
from chalice_cognito_auth.constants import CLIENT_ID_ENV_VAR
from chalice_cognito_auth.constants import USER_POOL_ID_ENV_VAR
from chalice_cognito_auth.constants import REGION_ENV_VAR
from chalice_cognito_auth.constants import DEFAULT_USER_POOL_HANDLER_NAME
from chalice_cognito_auth.constants import USER_POOL_HANDLER_NAME_ENV_VAR
from chalice_cognito_auth.utils import env_var


class UserPoolHandlerFactory:
    def __init__(self, blueprint_factory=None):
        if blueprint_factory is None:
            blueprint_factory = BlueprintFactory()
        self._blueprint_factory = blueprint_factory

    def create_user_pool_handler(self, app_client_id=None, user_pool_id=None,
                                 region=None, name=None):
        if app_client_id is None:
            app_client_id = env_var(CLIENT_ID_ENV_VAR)
        if user_pool_id is None:
            user_pool_id = env_var(USER_POOL_ID_ENV_VAR)
        if region is None:
            region = env_var(REGION_ENV_VAR)
        if name is None:
            name = DEFAULT_USER_POOL_HANDLER_NAME
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

    @classmethod
    def from_env(cls) -> 'UserPoolHandler':
        authorizer = UserPoolAuthorizer.from_env()
        blueprint, auth_wrapper = BlueprintFactory.from_env().create_blueprint(
            name=env_var(
                USER_POOL_HANDLER_NAME_ENV_VAR,
                DEFAULT_USER_POOL_HANDLER_NAME
            ),
            authorizer=authorizer,
            lifecycle=CognitoLifecycle.from_env(),
        )
        return cls(
            authorizer=authorizer,
            blueprint=blueprint,
            auth_wrapper=auth_wrapper,
        )

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

    @classmethod
    def from_env(cls) -> 'CognitoLifecycle':
        return cls(
            app_client_id=env_var(CLIENT_ID_ENV_VAR),
            user_pool_id=env_var(USER_POOL_ID_ENV_VAR),
            cognito=boto3.client(
                'cognito-idp',
                region_name=env_var(REGION_ENV_VAR),
            )
        )

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
        return result

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
