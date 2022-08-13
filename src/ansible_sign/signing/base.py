class SignatureVerificationResult:
    """Represents the result after performing signature verification."""

    def __init__(self, success, summary, extra_information={}):
        self.success = success
        self.summary = summary
        self.extra_information = extra_information

    def __bool__(self):
        return self.success


class SignatureVerifier:
    """
    Represents a way of performing content verification. It doesn't make any
    assumptions about the kind of verification being done.
    """

    def verify(self) -> SignatureVerificationResult:
        """
        Does the actual verification.

        Returns an instance of SignatureVerificationResult.
        """
        raise NotImplementedError("verify")


class SignatureSigningResult:
    """Represents the result after performing signing."""

    def __init__(self, success, summary, extra_information={}):
        self.success = success
        self.summary = summary
        self.extra_information = extra_information

    def __bool__(self):
        return self.success


class SignatureSigner:
    """
    Represents a way of signing content for later verification. This interface
    makes no assumptions about the kind of verification being done.
    """

    def sign(self):
        """
        Signs a file.
        """
        raise NotImplementedError("sign")
