from chalice_cognito_auth.userpool import UserPoolHandlerFactory
from chalice_cognito_auth.userpool import UserPoolHandler

import mock


def test_can_create_handler():
    factory = UserPoolHandlerFactory()
    handler = factory.create_user_pool_handler(
        'client_id', 'pool_id', region='mars-west-1', name='NAME')

    assert isinstance(handler, UserPoolHandler)
