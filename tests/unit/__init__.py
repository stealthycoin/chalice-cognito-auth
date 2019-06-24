import mock

import pytest

from chalice import app

from chalice_cognito_auth.blueprint import BlueprintFactory
from chalice_cognito_auth.userpool import UserPoolHandlerFactory


@pytest.fixture
def sample_app():
    demo = app.Chalice('app-name')
    return demo


def test_login_route(sample_app, create_event):
    factory = UserPoolHandlerFactory()
    handler = factory.create_user_pool_handler(
        sample_app, 'sample', 'client_id')
    sample_app.register_blueprint(handler.blueprint)

    event = create_event('/login', 'GET', None)
    response = sample_app(event, context=None)

    assert response['statusCode'] == 200
    assert response['body'] == 'login'


def test_logout_route(sample_app, create_event):
    factory = UserPoolHandlerFactory()
    handler = factory.create_user_pool_handler(
        sample_app, 'sample', 'client_id')
    sample_app.register_blueprint(handler.blueprint)

    event = create_event('/logout', 'GET', None)
    response = sample_app(event, context=None)

    assert response['statusCode'] == 200
    assert response['body'] == 'logout'
