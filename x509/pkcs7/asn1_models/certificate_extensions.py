# dslib imports
from pyasn1.type import tag, namedtype, univ

# local imports
from x509.pkcs7.asn1_models.tools import *
from x509.pkcs7.asn1_models.general_types import *

"""
Certificate extensions specifications
"""


# RDNS sequence otagovana A4 (constructed octet string)
class IssuerName(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("name", RDNSequence().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x4))),
    )


class KeyId(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType(
            "keyIdentifier", univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x0))
        ),
        namedtype.OptionalNamedType(
            "authorityCertIssuer", IssuerName().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x1))
        ),
        namedtype.OptionalNamedType(
            "authorityCertSerialNum", univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x2))
        ),
    )


class BasicConstraints(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType("ca", univ.Boolean(False)), namedtype.OptionalNamedType("pathLen", univ.Integer())
    )


class AnyQualifier(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("userNotice", univ.Sequence()),
        namedtype.NamedType("cpsUri", char.IA5String()),
    )


class PolicyQualifierInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("policyQualifierId", univ.ObjectIdentifier()), namedtype.OptionalNamedType("qualifier", AnyQualifier())
    )


class PolicyQualifiers(univ.SequenceOf):
    componentType = PolicyQualifierInfo()


class PolicyInformation(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("policyIdentifier", univ.ObjectIdentifier()),
        namedtype.OptionalNamedType("policyQualifiers", PolicyQualifiers()),
    )


class CertificatePolicies(univ.SequenceOf):
    componentType = PolicyInformation()


class DpointName(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("fullName", GeneralNames().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x0))),
        namedtype.NamedType(
            "relativeToIssuer",
            RelativeDistinguishedName().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x1)),
        ),
    )


class ReasonFlags(ConvertibleBitString):
    pass


class DistributionPoint(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType(
            "distPoint", DpointName().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x0))
        ),
        namedtype.OptionalNamedType(
            "reasons", ReasonFlags().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x1))
        ),
        namedtype.OptionalNamedType(
            "issuer", GeneralNames().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x2))
        ),
    )


class CRLDistributionPoints(univ.SequenceOf):
    componentType = DistributionPoint()


class AccessDescription(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("accessMethod", univ.ObjectIdentifier()),
        namedtype.NamedType("accessLocation", GeneralName()),
    )


class AuthorityInfoAccess(univ.SequenceOf):
    componentType = AccessDescription()


class ExtendedKeyUsage(univ.SequenceOf):
    componentType = univ.ObjectIdentifier()


class Statement(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("stmtId", univ.ObjectIdentifier()),
        namedtype.OptionalNamedType("stmtInfo", univ.Any()),
    )


class Statements(univ.SequenceOf):
    componentType = Statement()


class SubjectKeyId(univ.OctetString):
    pass


class PolicyConstraints(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType(
            "requireExplicitPolicy", univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x0))
        ),
        namedtype.OptionalNamedType(
            "inhibitPolicyMapping", univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x1))
        ),
    )


class GeneralSubtree(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("base", GeneralName()),
        namedtype.DefaultedNamedType(
            "minimum", univ.Integer(0).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x0))
        ),
        namedtype.OptionalNamedType(
            "maximum", univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x1))
        ),
    )


class GeneralSubtrees(univ.SequenceOf):
    componentType = GeneralSubtree()


class NameConstraints(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType(
            "permittedSubtrees", GeneralSubtrees().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x0))
        ),
        namedtype.OptionalNamedType(
            "excludedSubtrees", GeneralSubtrees().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x1))
        ),
    )


class NetscapeCertType(univ.BitString):
    pass


class ExtensionValue(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("subjectAltName", GeneralNames()),
        namedtype.NamedType("authKeyId", KeyId()),
        namedtype.NamedType("CRLdistPoints", univ.Sequence()),
        namedtype.NamedType("certPolicies", univ.Sequence()),
        namedtype.NamedType("basicConstraints", univ.Sequence()),
        namedtype.NamedType("keyUsage", ConvertibleBitString()),
        namedtype.NamedType("qcStatements", univ.Sequence()),
        namedtype.NamedType("subjectKeyId", KeyId()),
    )
