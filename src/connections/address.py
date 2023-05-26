class Address:
    def __init__(self, host, port):
        self.host = host
        self.port = port
    
    def get_host(self):
        return self.host
    
    def get_port(self):
        return self.port

    def __str__(self):
        return self.host + ":" + str(self.port)
    
    @staticmethod
    def from_string(host_and_port):
        split = host_and_port.split(":")
        if len(split) != 2:
            raise ValueError("Cannot construct Address from malformed host:port string '" + host_and_port + "'")
        host = split[0]
        try:
            port = int(split[1])
        except ValueError:
            raise ValueError("Cannot construct Address from malformed host:port string '" + host_and_port + "'")
        return Address(host, port)
