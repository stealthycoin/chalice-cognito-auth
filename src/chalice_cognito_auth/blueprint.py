import sys

from chalice import Blueprint
from chalice import Response

from chalice_cognito_auth.exceptions import InvalidAuthHandlerNameError
from chalice_cognito_auth.exceptions import ChallengeError
from chalice_cognito_auth.utils import get_param
from chalice_cognito_auth.utils import handle_client_errors
from chalice_cognito_auth.utils import is_running_on_lambda


class BlueprintFactory:
    def _rename_fn(self, name):
        def renamer(fn):
            def wrapped(*args, **kwargs):
                return fn(*args, **kwargs)
            wrapped.__name__ = name
            return wrapped
        return renamer

    @classmethod
    def from_env(cls) -> 'BlueprintFactory':
        return cls()

    def create_blueprint(self, name, authorizer, lifecycle):
        if name in vars(sys.modules[__name__]):
            raise InvalidAuthHandlerNameError(name)

        routes = Blueprint('%s' % __name__)

        @routes.authorizer(name=name)
        @self._rename_fn(name)
        def auth(auth_request):
            return authorizer.auth_handler(auth_request)

        @routes.route('/register', methods=['POST'])
        @handle_client_errors
        def register():
            body = routes.current_request.json_body
            username = get_param(body, 'username', required=True)
            password = get_param(body, 'password', required=True)
            body.pop('username')
            body.pop('password')
            return lifecycle.register(username, password, body)

        @routes.route('/confirm_registration', methods=['POST'])
        @handle_client_errors
        def confirm():
            body = routes.current_request.json_body
            username = get_param(body, 'username', required=True)
            code = get_param(body, 'code', required=True)
            lifecycle.confirm(username, code)

        @routes.route('/login', methods=['POST'])
        @handle_client_errors
        def login():
            body = routes.current_request.json_body
            username = get_param(body, 'username', required=True)
            password = get_param(body, 'password', required=True)
            try:
                return lifecycle.login(username, password)
            except ChallengeError as e:
                return Response(
                    body=e.params,
                    status_code=401,
                    headers={
                        'Challenge': e.challenge,
                        'Session': e.session,
                    }
                )

        @routes.route('/auth_challenge', methods=['POST'])
        @handle_client_errors
        def auth_challenge():
            body = routes.current_request.json_body
            challenge = get_param(body, 'challenge', required=True)
            session = get_param(body, 'session', required=True)
            params = get_param(body, 'params', required=True)
            return lifecycle.auth_challenge(challenge, session, params)

        @routes.route('/refresh', methods=['POST'])
        @handle_client_errors
        def refresh():
            body = routes.current_request.json_body
            refresh_token = get_param(body, 'refresh_token', required=True)
            return lifecycle.refresh(refresh_token)

        setattr(sys.modules[__name__], name, auth)
        return routes, auth


def _import_chalice_app_if_needed():
    # Chalice isn't loaded in an authorizer because the lambda handler string
    # does not load the app.* file. It loads chalice_cognito_auth.blueprint.*
    # instead. This causes create_blueprint not to get called (since it is
    # called in app.py) and hence it prevents the authorizer handler function
    # from getting injected into this module. This method is called on module
    # load to include app.py (hence calling create_blueprint) and preventing
    # a circular import.
    if 'app' in sys.modules:
        return
    import app  # noqa


if is_running_on_lambda():
    _import_chalice_app_if_needed()
