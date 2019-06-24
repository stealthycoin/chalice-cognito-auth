class InvalidToken(Exception):
    pass


class InvalidAuthHandlerNameError(Exception):
    """InvalidAuthHandlerNameError

    The names of auth handlers must be unique.
    """
    def __init__(self, name):
        self.message = 'Duplicate auth handler name %s found.' % name
        self.duplicate_name = name
