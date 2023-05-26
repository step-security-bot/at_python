import ssl
from src.connections import AtConnection, Address


class AtSecondaryConnection(AtConnection):
    """
    Subclass of AtConnection representing a connection to the secondary server in the atprotocol.
    """

    def __init__(self, address: Address, context:ssl.SSLContext=ssl.create_default_context(), verbose:bool=False):
        """
        Initialize the AtSecondaryConnection object.

        Parameters
        ----------
        host : str
            The host name or IP address of the secondary server.
        port : int
            The port number of the secondary server.
        context : ssl.SSLContext, optional
            The SSL context for secure connections (default is ssl.create_default_context()).
        verbose : bool, optional
            Indicates if verbose output is enabled (default is False).
        """
        super().__init__(address.get_host(), address.get_port(), context, verbose)

    def connect(self):
        """
        Establish a connection to the secondary server.
        """
        super().connect()
        if self.verbose:
            print("Secondary Connection Successful")

    def parse_raw_response(self, raw_response:str):
        """
        Parse the raw response from the secondary server.

        Parameters
        ----------
        raw_response : str
            The raw response received from the secondary server.

        Returns
        -------
        str
            The parsed response from the secondary server.
        """
        if raw_response.endswith("@"):
            raw_response = raw_response[:-1]
        raw_response = raw_response.strip()

        return raw_response
