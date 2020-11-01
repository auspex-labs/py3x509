# dslib imports
from pyasn1.type import namedtype, univ

# local imports
from general_types import AlgorithmIdentifier


class DigestInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("digestAgorithm", AlgorithmIdentifier()), namedtype.NamedType("digest", univ.OctetString())
    )
