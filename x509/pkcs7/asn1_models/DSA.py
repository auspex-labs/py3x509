from pyasn1.type import namedtype, univ

# 7.3.3  DSA Signature Keys
#
# Dss-Parms  ::=  SEQUENCE  {
#    p             INTEGER,
#    q             INTEGER,
#    g             INTEGER  }


class DsaPubKey(univ.Integer):
    pass


class DssParams(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("p", univ.Integer()),
        namedtype.NamedType("q", univ.Integer()),
        namedtype.NamedType("g", univ.Integer()),
    )
