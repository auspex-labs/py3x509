import base64
import hashlib
import logging

logger = logging.getLogger("pkcs7.digest")

RSA_NAME = "RSA"


class LazyB64:
    """
    Lazy base 64 converter for logging.
    """

    def __init__(self, data):
        self.data = data

    def __str__(self):
        return base64.b64encode(self.data)


def calculate_digest(data, alg):
    """
    Calculates digest according to algorithm
    """
    try:
        alg = alg.replace("-", "")
        digest = hashlib.new(alg, data).digest()
        logger.debug("Calculated hash from input data: %s", LazyB64(digest))
        return digest
    except ValueError:
        logger.error("Unknown digest algorithm : %s", alg)
        raise
