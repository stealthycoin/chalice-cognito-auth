import pytest
import mock

from chalice_cognito_auth.userpool import UserPoolHandlerFactory
from chalice_cognito_auth.userpool import UserPoolHandler
from chalice_cognito_auth.userpool import CognitoLifecycle
from chalice_cognito_auth.exceptions import ChallengeError


@pytest.fixture
def cognito_lifecycle():
    mock_cognito = mock.Mock()
    return mock_cognito, CognitoLifecycle('client_id', 'pool_id', mock_cognito)


def test_can_create_handler():
    factory = UserPoolHandlerFactory()
    handler = factory.create_user_pool_handler(
        'client_id', 'pool_id', region='mars-west-1', name='NAME')

    assert isinstance(handler, UserPoolHandler)


class TestCognitoLifecycle:
    def test_can_login(self, cognito_lifecycle):
        cognito, lifecycle = cognito_lifecycle
        cognito.initiate_auth.return_value = {
            'AuthenticationResult': {
                'AccessToken': 'access',
                'IdToken': 'id',
                'RefreshToken': 'refresh',
                'TokenType': 'type',
            }
        }
        result = lifecycle.login('foo', 'bar')

        cognito.initiate_auth.assert_called_with(
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': 'foo',
                'PASSWORD': 'bar',
            },
            ClientId='client_id',
        )
        assert result == {
            'access_token': 'access',
            'id_token': 'id',
            'refresh_token': 'refresh',
            'token_type': 'type',
        }

    def test_can_return_password_reset_challenge(self, cognito_lifecycle):
        cognito, lifecycle = cognito_lifecycle
        cognito.initiate_auth.return_value = {
            'ChallengeName': 'NEW_PASSWORD_REQUIRED',
            'Session': 'sessionstring',
            'ChallengeParameters': {
                'USER_ID_FOR_SRP': 'foo',
            }
        }
        with pytest.raises(ChallengeError) as e:
            lifecycle.login('foo', 'bar')

        cognito.initiate_auth.assert_called_with(
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': 'foo',
                'PASSWORD': 'bar',
            },
            ClientId='client_id',
        )
        assert e.value.challenge == 'NEW_PASSWORD_REQUIRED'
        assert e.value.session == 'sessionstring'
        assert e.value.params == {
            'USER_ID_FOR_SRP': 'foo',
        }

    def test_can_refresh(self, cognito_lifecycle):
        cognito, lifecycle = cognito_lifecycle
        cognito.initiate_auth.return_value = {
            'AuthenticationResult': {
                'AccessToken': 'access',
                'IdToken': 'id',
                'RefreshToken': 'refresh',
                'TokenType': 'type',
            }
        }
        result = lifecycle.refresh('token')

        cognito.initiate_auth.assert_called_with(
            AuthFlow='REFRESH_TOKEN_AUTH',
            AuthParameters={
                'REFRESH_TOKEN': 'token',
            },
            ClientId='client_id',
        )
        assert result == {
            'access_token': 'access',
            'id_token': 'id',
            'refresh_token': 'refresh',
            'token_type': 'type',
        }

    def test_can_respond_to_auth_challenge(self, cognito_lifecycle):
        cognito, lifecycle = cognito_lifecycle
        cognito.respond_to_auth_challenge.return_value = {
            'AuthenticationResult': {
                'AccessToken': 'access',
                'IdToken': 'id',
                'RefreshToken': 'refresh',
                'TokenType': 'type',
            }
        }
        result = lifecycle.auth_challenge(
            'challenge',
            'session',
            {'foo': 'bar'},
        )
        cognito.respond_to_auth_challenge.assert_called_with(
            ChallengeName='challenge',
            Session='session',
            ChallengeResponses={'foo': 'bar'},
            ClientId='client_id',
        )
        assert result == {
            'access_token': 'access',
            'id_token': 'id',
            'refresh_token': 'refresh',
            'token_type': 'type',
        }
