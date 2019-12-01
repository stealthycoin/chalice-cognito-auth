import os
from collections import namedtuple
from typing import Dict

from botocore.exceptions import ClientError
from chalice import BadRequestError
from chalice import UnauthorizedError
from chalice import ChaliceViewError

from chalice_cognito_auth.exceptions import MissingEnvironmentVariableError


Error = namedtuple('Error', ['cls', 'fmt_str'])
CODE_TO_ERROR = {
    'NotAuthorizedException': Error(UnauthorizedError, '{message}'),
    'UserNotFoundException': Error(UnauthorizedError, '{message}'),
}
DEFAULT_ERROR = Error(ChaliceViewError, '{code}: {message}')


def get_param(body, key, required=False, default=None):
    try:
        return body[key]
    except KeyError as e:
        if required is False:
            return default
        key = e.args[0]
        raise BadRequestError('Missing requred parameter: %s' % key)


def client_error_to_chalice_error(e):
    code = e.response['Error']['Code']
    message = e.response['Error']['Message']
    error = CODE_TO_ERROR.get(code, DEFAULT_ERROR)
    raise error.cls(error.fmt_str.format(code=code, message=message))


def handle_client_errors(fn):
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except ClientError as e:
            client_error_to_chalice_error(e)
    return wrapped


def env_var(
        key: str,
        default: str = None,
        env: Dict[str, str] = os.environ,
) -> str:
    try:
        return env[key]
    except KeyError:
        if default is None:
            raise MissingEnvironmentVariableError(key)
        return default


def is_running_on_lambda(env: Dict[str, str] = os.environ):
    execution_env = env.get("AWS_EXECUTION_ENV", None)
    if execution_env is None:
        return False
    return execution_env.startswith('AWS_Lambda')
