class AtSign:
    def __init__(self, atsign):
        if atsign is None or atsign.strip() == "":
            raise ValueError("atSign may not be null or empty")

        self.atsign = self.format_atsign(atsign)

        if self.atsign == "@":
            raise ValueError(f"'{self.atsign}' is not a valid atSign")

        self.without_prefix = self.atsign[1:]

    def without_prefix(self):
        """
        Returns an atsign without @ prefix

        Returns
        -------
        str
            An atsign without prefix (e.g. "@alice " --> "alice").
        """
        return self.without_prefix

    def __str__(self):
        return self.atsign

    def __eq__(self, other):
        if self is other:
            return True
        if not isinstance(other, AtSign):
            return False
        return self.atsign == other.atsign

    @staticmethod
    def format_atsign(atsign_str):
        """
        Returns a formatted atsign

        Parameters
        ----------
        atsign_str : str
            The atsign string like "@bob".

        Returns
        -------
        str
            A formatted atsign (e.g. "alice " --> "@alice").
        """
        atsign_str = atsign_str.strip()
        if not atsign_str.startswith("@"):
            atsign_str = "@" + atsign_str
        return atsign_str
