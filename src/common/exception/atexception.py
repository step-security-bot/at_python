class AtException(Exception):
    """
    Custom exception class for AtConnection.
    """

    def __init__(self, message):
        """
        Initialize the AtException object.

        Parameters:
        - message (str): The error message associated with the exception.
        """
        super().__init__(message)
