class SignatureVerificationResult:
    """Represents the result after performing signature verification."""

    def __init__(self, success, summary, extra_information={}):
        self.success = success
        self.summary = summary
        self.extra_information = extra_information


class SignatureVerifier:
    """
    Represents a way of performing content verification. It doesn't make any
    assumptions about the kind of verification being done. The constructor takes
    raw parameters from the action, and subclasses can make use of those as
    needed to perform whatever kind of verification they want to.
    """

    def verify(self) -> SignatureVerificationResult:
        """
        Does the actual verification.

        Returns an instance of SignatureVerificationResult.
        """
        raise NotImplementedError("verify")
