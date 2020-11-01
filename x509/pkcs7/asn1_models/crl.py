# dslib imports
from pyasn1.type import tag, namedtype, univ

# local imports
from general_types import *
from X509_certificate import *

"""
Model of CRL
"""

"""
CertificateList  ::=  SEQUENCE  {
        tbsCertList          TBSCertList,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING  }

   TBSCertList  ::=  SEQUENCE  {
        version                 Version OPTIONAL,
                                     -- if present, MUST be v2
        signature               AlgorithmIdentifier,
        issuer                  Name,
        thisUpdate              Time,
        nextUpdate              Time OPTIONAL,
        revokedCertificates     SEQUENCE OF SEQUENCE  {
             userCertificate         CertificateSerialNumber,
             revocationDate          Time,
             crlEntryExtensions      Extensions OPTIONAL
                                      -- if present, version MUST be v2
                                  }  OPTIONAL,
        crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
                                      -- if present, version MUST be v2
                                  }

"""


class RevokedCertInfo(univ.Sequence):
    """
    univ.Any type is used instead of this type to avoid
    unnecessary parsing.
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("userCertificate", CertificateSerialNumber()),
        namedtype.NamedType("revocationDate", Time()),
        namedtype.OptionalNamedType("crlEntryExts", univ.Any()),
    )


class RevokedCertList(univ.Any):
    pass


class TbsCertList(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType("version", Version()),
        namedtype.NamedType("signature", AlgorithmIdentifier()),
        namedtype.NamedType("issuer", Name()),
        namedtype.NamedType("thisUpdate", Time()),
        namedtype.OptionalNamedType("nextUpdate", Time()),
        namedtype.OptionalNamedType("revokedCertificates", RevokedCertList()),
        namedtype.OptionalNamedType(
            "crlExtensions", Extensions().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x0))
        ),
    )


class RevCertificateList(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("tbsCertList", TbsCertList()),
        namedtype.NamedType("signatureAlgorithm", AlgorithmIdentifier()),
        namedtype.NamedType("signatureValue", ConvertibleBitString()),
    )
