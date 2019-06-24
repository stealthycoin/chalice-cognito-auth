import mock
import pytest

from chalice.app import AuthRequest

from chalice_cognito_auth.authorizer import RouteSelector
from chalice_cognito_auth.authorizer import PrincipalSelector
from chalice_cognito_auth.authorizer import AllRoutes
from chalice_cognito_auth.authorizer import UsernameSelector
from chalice_cognito_auth.authorizer import UserPoolAuthorizer
from chalice_cognito_auth.decoder import TokenDecoder
from chalice_cognito_auth.exceptions import InvalidToken


class TestUserPoolAuthorizer():
    def test_can_authorize_request(self):
        claims = {'claims': 'dict'}
        token = 'token'
        route_selector = mock.Mock(spec=RouteSelector)
        route_selector.get_allowed_routes.return_value = ['route']
        principal_selector = mock.Mock(spec=PrincipalSelector)
        principal_selector.get_principal.return_value = 'username'
        decoder = mock.Mock(spec=TokenDecoder)
        decoder.decode.return_value = claims
        authorizer = UserPoolAuthorizer(
            decoder,
            route_selector=route_selector,
            principal_selector=principal_selector,
        )
        request = mock.Mock(spec=AuthRequest)
        request.token = token
        response = authorizer.auth_handler(request)

        assert response.routes == ['route']
        assert response.principal_id == 'username'
        decoder.decode.assert_called_with(token)
        route_selector.get_allowed_routes.assert_called_with(claims)
        principal_selector.get_principal.assert_called_with(claims)

    def test_can_authorize_request_with_default_selectors(self):
        claims = {'cognito:username': 'username'}
        token = 'token'
        decoder = mock.Mock(spec=TokenDecoder)
        decoder.decode.return_value = claims
        authorizer = UserPoolAuthorizer(decoder)
        request = mock.Mock(spec=AuthRequest)
        request.token = token
        response = authorizer.auth_handler(request)

        assert response.routes == ['*']
        assert response.principal_id == 'username'
        decoder.decode.assert_called_with(token)

    def test_can_deny_request(self):
        claims = {'claims': 'dict'}
        token = 'token'
        route_selector = mock.Mock(spec=RouteSelector)
        route_selector.get_allowed_routes.return_value = ['route']
        principal_selector = mock.Mock(spec=PrincipalSelector)
        principal_selector.get_principal.return_value = 'username'
        decoder = mock.Mock(spec=TokenDecoder)
        decoder.decode.side_effect = InvalidToken()
        authorizer = UserPoolAuthorizer(
            decoder,
            route_selector=route_selector,
            principal_selector=principal_selector,
        )
        request = mock.Mock(spec=AuthRequest)
        request.token = token
        response = authorizer.auth_handler(request)

        assert response.routes == []
        assert response.principal_id is None
        decoder.decode.assert_called_with(token)
        route_selector.get_allowed_routes.assert_not_called()
        principal_selector.get_principal.assert_not_called()


def test_all_routes_route_selector():
    selector = AllRoutes()
    result = selector.get_allowed_routes({})
    assert result == ['*']


def test_username_principal_selector():
    selector = UsernameSelector()
    result = selector.get_principal({'cognito:username': 'john'})
    assert result == 'john'


def test_username_principal_selector_returns_none_if_key_missing():
    selector = UsernameSelector()
    result = selector.get_principal({})
    assert result is None
