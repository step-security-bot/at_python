from enum import Enum
from abc import ABC, abstractmethod

class VerbBuilder(ABC):
    @abstractmethod
    def build(self):
        raise NotImplementedError("Subclasses must implement the build() method")


class FromVerbBuilder(VerbBuilder):
    def __init__(self):
        self.shared_by = ""

    def set_shared_by(self, shared_by):
        self.shared_by = shared_by
        return self

    def build(self):
        return f"from:{self.shared_by}"

class PKAMVerbBuilder(VerbBuilder):
    def __init__(self):
        self.digest = ""

    def set_digest(self, digest):
        self.digest = digest
        return self

    def build(self):
        return f"pkam:{self.digest}"


class ScanVerbBuilder:
    def __init__(self):
        self.regex = None
        self.from_at_sign = None
        self.show_hidden = False

    def set_regex(self, regex):
        self.regex = regex
        return self

    def set_from_at_sign(self, from_at_sign):
        self.from_at_sign = from_at_sign
        return self

    def set_show_hidden(self, show_hidden):
        self.show_hidden = show_hidden
        return self

    def build(self):
        command = "scan"

        if self.show_hidden:
            command += ":showHidden:true"

        if self.from_at_sign is not None and self.from_at_sign.strip() != "":
            command += ":" + self.from_at_sign

        if self.regex is not None and self.regex.strip() != "":
            command += " " + self.regex

        return command
