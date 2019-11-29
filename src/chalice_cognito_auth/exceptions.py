class InvalidToken(Exception):
    pass


class InvalidAuthHandlerNameError(Exception):
    """InvalidAuthHandlerNameError

    The names of auth handlers must be unique.
    """
    def __init__(self, name):
        self.message = 'Duplicate auth handler name %s found.' % name
        self.duplicate_name = name


class ChallengeError(Exception):
    """ChallengeError

    Raised during login when an additional challenge needs to be passed before
    login.
    """
    def __init__(self, challenge, session, params):
        self.challenge = challenge
        self.session = session
        self.params = params


class MissingEnvironmentVariableError(Exception):
    def __init__(self, name):
        self.name = name

    def __str__(self) -> str:
        return f'Could not find required environment variable: "{self.name}".'
