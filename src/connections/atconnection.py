import socket
import ssl
from abc import ABC, abstractmethod

from common.exception import AtException


class AtConnection(ABC):
    """
    Abstract base class for connecting to and communicating with an atprotocol server.
    """

    def __init__(self, host:str, port:int, context:ssl.SSLContext, verbose:bool=False):
        """
        Initialize the AtConnection object.

        Parameters:
        - host (str): The host name or IP address of the server.
        - port (int): The port number of the server.
        - context (ssl.SSLContext): The SSL context for secure connections.
        - verbose (bool, optional): Indicates if verbose output is enabled (default is False).
        """
        self.host = host
        self.port = port
        self.context = context
        self.addr_info = socket.getaddrinfo(host, port)[0][-1]
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.secure_root_socket = None
        self.verbose = verbose

    def __str__(self):
        """
        Return a string representation of the AtConnection object.

        Returns:
        - str: A string representation of the AtConnection object in the format "host:port".
        """
        return f"{self.host}:{self.port}"

    def write(self, data: str):
        """
        Write data to the socket.

        Parameters:
        - data (str): The data to be written to the socket.
        """
        self.secure_root_socket.write(data.encode())

    def read(self):
        """
        Read data from the socket.

        Returns:
        - str: The data read from the socket.
        """
        response = b''
        data = self.secure_root_socket.read(2048)
        response += data
        return response.decode()

    def is_connected(self):
        """
        Check if the connection is established.

        Returns:
        - bool: True if the connection is established, False otherwise.
        """
        return self.connected

    def connect(self):
        """
        Establish a connection to the server. Throws IOException
        """
        if not self.connected:
            self._socket.connect(self.addr_info)
            self.secure_root_socket = self.context.wrap_socket(
                self._socket, server_hostname=self.host, do_handshake_on_connect=True
            )
            self.connected = True
            self.read()

    def disconnect(self):
        """
        Close the socket connection.
        """
        self.secure_root_socket.close()
        self.connected = False

    @abstractmethod
    def parse_raw_response(self, raw_response:str):
        """
        Parse the raw response from the server.

        Parameters:
        - raw_response (str): The raw response received from the server.
        """
        pass

    def execute_command(self, command:str, retry_on_exception:int=0, read_the_response:bool=True):
        """
        Execute a command and retrieve the response from the server.

        Parameters:
        - command (str): The command to be executed.
        - retry_on_exception (int, optional): The number of times to retry the command if an exception occurs (default is 0).
        - read_the_response (bool, optional): Indicates if the response should be read from the server (default is True).

        Returns:
        - str: The response from the server.
        """
        try:
            if not command.endswith("\n"):
                command += "\n"
            self.write(command)

            if self.verbose:
                print(f"\tSENT: {repr(command.strip())}")

            if read_the_response:
                raw_response = self.read()
                if self.verbose:
                    print(f"\tRCVD: {repr(raw_response)}")

                return self.parse_raw_response(raw_response)
            else:
                return ""
        except Exception as first:
            if retry_on_exception:
                print(f"\tCaught exception {str(first)}: reconnecting")
                try:
                    self.connect()
                    return self.execute_command(command, False, True)
                except Exception as second:
                    import traceback
                    traceback.print_exc()
                    raise AtException(f"Failed to reconnect after original exception {str(first)}: ", second)
            else:
                self.connected = False
                raise AtException(str(first))
