from dataclasses import dataclass

@dataclass
class Attestation:
    complete: bool
    expected: int
    received: int
    missing: list[int]

class CCA:

    def __init__(self):
        self.last = 0

    def verify(self, seq):

        if self.last == 0:
            self.last = seq
            return Attestation(True, seq, seq, [])

        expected = self.last + 1

        if seq == expected:
            self.last = seq
            return Attestation(True, expected, seq, [])

        missing = list(range(expected, seq))

        self.last = seq

        return Attestation(False, expected, seq, missing)