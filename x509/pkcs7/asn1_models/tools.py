from x509.pkcs7.asn1_models.decoder_workarounds import decode
from x509.pkcs7.asn1_models.RSA import RsaPubKey
from x509.pkcs7.asn1_models.DSA import DssParams, DsaPubKey

"""
Some useful tools for working with ASN1 components.
"""


def tuple_to_OID(tuple):
    """
    Converts OID tuple to OID string
    """
    l = len(tuple)
    buf = ""
    for idx in range(l):
        if idx < l - 1:
            buf += str(tuple[idx]) + "."
        else:
            buf += str(tuple[idx])
    return buf


def get_RSA_pub_key_material(subjectPublicKeyAsn1):
    """
    Extracts modulus and public exponent from
    ASN1 bitstring component subjectPublicKey
    """
    # create template for decoder
    rsa_key = RsaPubKey()
    # convert ASN1 subjectPublicKey component from BITSTRING to octets
    pubkey = subjectPublicKeyAsn1.toOctets()

    key = decode(pubkey, asn1Spec=rsa_key)[0]

    mod = key.getComponentByName("modulus")._value
    exp = key.getComponentByName("exp")._value

    return {"mod": mod, "exp": exp}


def get_DSA_pub_key_material(subjectPublicKeyAsn1, parametersAsn1):
    """
    Extracts DSA parameters p, q, g from
    ASN1 bitstring component subjectPublicKey and parametersAsn1 from
    'parameters' field of AlgorithmIdentifier.
    """
    pubkey = subjectPublicKeyAsn1.toOctets()

    key = decode(pubkey, asn1Spec=DsaPubKey())[0]
    parameters = decode(str(parametersAsn1), asn1Spec=DssParams())[0]
    paramDict = {"pub": int(key)}

    for param in ["p", "q", "g"]:
        paramDict[param] = parameters.getComponentByName(param)._value

    return paramDict
