from pyasn1.type import univ, namedtype, constraint, namedval, char, tag

class Opaque(univ.OctetString):
    pass

class Ieee1609Dot2Content(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('unsecureData', Opaque()),
    )

class Uint8(univ.Integer):
    subtypeSpec = constraint.ValueRangeConstraint(0, 255)

class Ieee1609Dot2Data(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('protocolVersion', Uint8()),
        namedtype.NamedType('content', Ieee1609Dot2Content())
    )