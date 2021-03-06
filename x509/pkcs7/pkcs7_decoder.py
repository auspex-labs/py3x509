from cStringIO import StringIO

# dslib imports
from asn1_models.decoder_workarounds import decode

# local imports
from asn1_models.pkcs_signed_data import *
from asn1_models.digest_info import *
from asn1_models.TST_info import *


class StringView(object):
    def __init__(self, string, start, end):
        self._string = string
        self._start = start
        if end is None:
            self._end = len(string)
        else:
            self._end = end

    def __len__(self):
        return self._end - self._start

    def __getitem__(self, key):
        if type(key) == int:
            if key < 0:
                self._string.seek(self._end + key)
                return self._string.read(1)
            if key >= (self._end - self._start):
                raise IndexError()
            self._string.seek(self._start + key)
            return self._string.read(1)
        elif type(key) == slice:
            if key.stop is None:
                end = self._end
            elif key.stop < 0:
                end = self._end + key.stop
            else:
                end = self._start + key.stop
            start = self._start + (key.start or 0)
            return StringView(self._string, start=start, end=end)
        else:
            raise IndexError()

    def __str__(self):
        self._string.seek(self._start)
        return self._string.read(self._end - self._start)

    def __nonzero__(self):
        return len(self)


def decode_msg(message):
    """
    Decodes message in DER encoding.
    Returns ASN1 message object
    """
    # create template for decoder
    msg = Message()
    # decode pkcs signed message
    mess_obj = StringIO(message)
    mess_view = StringView(mess_obj, 0, len(message))
    decoded = decode(mess_view, asn1Spec=msg)
    message = decoded[0]
    return message


def decode_qts(qts_bytes):
    """
    Decodes qualified timestamp
    """
    qts = Qts()
    decoded = decode(qts_bytes, asn1Spec=qts)
    qts = decoded[0]

    return qts


def decode_tst(tst_bytes):
    """
    Decodes Timestamp Token
    """
    tst = TSTInfo()
    decoded = decode(tst_bytes, asn1Spec=tst)
    tst = decoded[0]

    return tst
