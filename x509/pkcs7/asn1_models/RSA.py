# dslib imports
from pyasn1.type import tag, namedtype, univ


class Modulus(univ.OctetString):
    tagSet = univ.OctetString.tagSet.tagImplicitly(tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 0x02))


class RsaPubKey(univ.Sequence):
    componentType = namedtype.NamedTypes(namedtype.NamedType("modulus", Modulus()), namedtype.NamedType("exp", univ.Integer()))
