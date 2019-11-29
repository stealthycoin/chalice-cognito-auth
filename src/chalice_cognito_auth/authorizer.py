from chalice import AuthResponse

from chalice_cognito_auth.exceptions import InvalidToken
from chalice_cognito_auth.decoder import TokenDecoder


class UserPoolAuthorizer:
    def __init__(self, decoder, route_selector=None, principal_selector=None):
        self._decoder = decoder

        if route_selector is None:
            route_selector = AllRoutes()
        self._route_selector = route_selector

        if principal_selector is None:
            principal_selector = UsernameSelector()
        self._principal_selector = principal_selector

    @classmethod
    def from_env(cls) -> 'UserPoolAuthorizer':
        return cls(decoder=TokenDecoder.from_env())

    def auth_handler(self, auth_request):
        token = auth_request.token
        try:
            claims = self._decoder.decode(token)
            return AuthResponse(
                self._route_selector.get_allowed_routes(claims),
                principal_id=self._principal_selector.get_principal(claims),
            )
        except InvalidToken:
            return AuthResponse(routes=[], principal_id=None)


class RouteSelector:
    def get_allowed_routes(self, claims):
        raise NotImplementedError('get_allowed_routes')


class AllRoutes(RouteSelector):
    def get_allowed_routes(self, claims):
        return ['*']


class PrincipalSelector:
    def get_principal(self, claims):
        raise NotImplementedError('get_principal')


class UsernameSelector(PrincipalSelector):
    def get_principal(self, claims):
        return claims.get('cognito:username')
