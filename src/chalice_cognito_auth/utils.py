from collections import namedtuple

from botocore.exceptions import ClientError
from chalice import BadRequestError
from chalice import UnauthorizedError
from chalice import ChaliceViewError


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
