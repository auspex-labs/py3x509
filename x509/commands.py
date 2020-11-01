import sys
from x509.models import PKCS7
from x509.models import X509Certificate


def print_certificate_info(derData):
    """
    Print certificate to stdout
    """
    X509Certificate.from_der(derData).display()


def print_certificate_info_cmd():
    """
    Print certificate command
    """
    if len(sys.argv) < 2:
        # print >>sys.stderr, "Usage: %s <certicate file>" % sys.argv[0]
        sys.exit(1)
    print_certificate_info(file(sys.argv[1]).read())


def print_signature_info(derData):
    """
    Print signature certificates to stdout
    """
    PKCS7.from_der(derData).display()


def print_signature_info_cmd():
    """
    Print signature certificates command
    """
    if len(sys.argv) < 2:
        # print >>sys.stderr, "Usage: %s <pkcs 7 signature file>" % sys.argv[0]
        sys.exit(1)
    print_signature_info(file(sys.argv[1]).read())


def print_timestamp_info(derData):
    """
    Print timestamp info
    """
    pkcs7 = PKCS7.from_der(derData)
    signedDate, valid_from, valid_to, signer = pkcs7.get_timestamp_info()
    print("Signature date: %s" % signedDate)
    print("Signers certicate valid from: %s, to: %s" % (valid_from, valid_to))
    print("Signers certicate sbject: %s" % signer)


def print_timestamp_info_cmd():
    """
    Print timestamp data
    """
    if len(sys.argv) < 2:
        # print >>sys.stderr, "Usage: %s <pkcs 7 signature file>" % sys.argv[0]
        sys.exit(1)
    print_timestamp_info(file(sys.argv[1]).read())
