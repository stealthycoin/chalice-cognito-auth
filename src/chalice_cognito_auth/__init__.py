__version__ = '2.4.1'
from chalice_cognito_auth.userpool import UserPoolHandler


def default_user_pool_handler() -> UserPoolHandler:
    return UserPoolHandler.from_env()
