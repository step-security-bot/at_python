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