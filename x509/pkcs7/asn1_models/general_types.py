# dslib imports
from pyasn1.type import tag, namedtype, univ, char

# local imports
from x509.pkcs7.asn1_models.tools import *
from x509.pkcs7.asn1_models.oid import *


class ConvertibleBitString(univ.BitString):
    """
    Extends uni.BitString with method that converts value
    to the octet string.
    """

    def toOctets(self):
        # oh $deity, please FIXME
        """
        Converts bit string into octets string
        """

        def _tuple_to_byte(tuple):
            # return chr(int(''.join(map(str, tuple)),2))
            return int("".join(map(str, tuple)), 2).to_bytes(1, byteorder="big")

        res = b""
        byte_len = int(len(self._value) / 8)
        for byte_idx in range(byte_len):
            bit_idx = byte_idx * 8
            byte_tuple = self._value[bit_idx : bit_idx + 8]
            byte = _tuple_to_byte(byte_tuple)
            res += byte
        return res


class DirectoryString(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("teletexString", char.TeletexString()),
        namedtype.NamedType("printableString", char.PrintableString()),
        namedtype.NamedType("universalString", char.UniversalString()),
        namedtype.NamedType("utf8String", char.UTF8String()),
        namedtype.NamedType("bmpString", char.BMPString()),
        namedtype.NamedType("ia5String", char.IA5String()),  # for legacy pkcs9-email
        # namedtype.NamedType('gString', univ.OctetString()),
        namedtype.NamedType("bitString", univ.BitString()),  # needed for X500 Unique Identifier, RFC 4519
    )

    def __repr__(self):
        try:
            c = self.getComponent()
            return c.__str__()
        except:
            return "Choice type not chosen"

    def __str__(self):
        return repr(self)


class AttributeValue(DirectoryString):
    pass


class AttributeType(univ.ObjectIdentifier):
    def __str__(self):
        return tuple_to_OID(self._value)


class AttributeTypeAndValue(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("type", AttributeType()), namedtype.NamedType("value", AttributeValue())
    )

    def __repr__(self):
        # s = "%s => %s" % [ self.getComponentByName('type'), self.getComponentByName('value')]
        type = self.getComponentByName("type")
        value = self.getComponentByName("value")
        s = "%s => %s" % (type, value)
        return s

    def __str__(self):
        return self.__repr__()


class RelativeDistinguishedName(univ.SetOf):
    componentType = AttributeTypeAndValue()

    def __str__(self):
        buf = ""
        for component in self._componentValues:
            buf += str(component)
            buf += ","
        buf = buf[: len(buf) - 1]
        return buf


class RDNSequence(univ.SequenceOf):
    componentType = RelativeDistinguishedName()

    def __str__(self):
        buf = ""
        for component in self._componentValues:
            buf += str(component)
            buf += ","
        buf = buf[: len(buf) - 1]
        return buf


class Name(univ.Choice):
    componentType = namedtype.NamedTypes(namedtype.NamedType("", RDNSequence()))

    def __str__(self):
        return str(self.getComponent())


class AlgorithmIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("algorithm", univ.ObjectIdentifier()),
        namedtype.OptionalNamedType("parameters", univ.Any())
        # XXX syntax screwed?
        #        namedtype.OptionalNamedType('parameters', univ.ObjectIdentifier())
    )

    def __repr__(self):
        tuple = self.getComponentByName("algorithm")
        str_oid = tuple_to_OID(tuple)
        return str_oid

    def __str__(self):
        return repr(self)


class UniqueIdentifier(ConvertibleBitString):
    pass


"""
GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName

GeneralName ::= CHOICE {
     otherName                       [0]     AnotherName,
     rfc822Name                      [1]     IA5String,
     dNSName                         [2]     IA5String,
     x400Address                     [3]     ORAddress,
     directoryName                   [4]     Name,
     ediPartyName                    [5]     EDIPartyName,
     uniformResourceIdentifier       [6]     IA5String,
     iPAddress                       [7]     OCTET STRING,
     registeredID                    [8]     OBJECT IDENTIFIER }

-- AnotherName replaces OTHER-NAME ::= TYPE-IDENTIFIER, as
-- TYPE-IDENTIFIER is not supported in the '88 ASN.1 syntax

AnotherName ::= SEQUENCE {
     type-id    OBJECT IDENTIFIER,
     value      [0] EXPLICIT ANY DEFINED BY type-id }

EDIPartyName ::= SEQUENCE {
     nameAssigner            [0]     DirectoryString OPTIONAL,
     partyName               [1]     DirectoryString }

"""


class GeneralName(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "otherName", univ.Sequence().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x0))
        ),
        namedtype.NamedType(
            "rfc822Name", char.IA5String().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x1))
        ),
        namedtype.NamedType(
            "dNSName", char.IA5String().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x2))
        ),
        namedtype.NamedType(
            "x400Address", univ.Sequence().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x3))
        ),
        namedtype.NamedType(
            "directoryName", Name().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x4))
        ),
        namedtype.NamedType(
            "ediPartyName", univ.Sequence().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x5))
        ),
        namedtype.NamedType(
            "uniformResourceIdentifier",
            char.IA5String().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x6)),
        ),
        namedtype.NamedType(
            "iPAddress", univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x7))
        ),
        namedtype.NamedType(
            "registeredID", univ.ObjectIdentifier().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x8))
        ),
    )


class GeneralNames(univ.SequenceOf):
    componentType = GeneralName()

    def __str__(self):
        ret = ""
        for part in self._componentValues:
            ret += str(part.getComponent())
            ret += " ; "
        return ret[: len(ret) - 1]
