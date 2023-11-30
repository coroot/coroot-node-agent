package l7

import (
	"encoding/binary"

	"go.mongodb.org/mongo-driver/bson"
)

const (
	MongoOpMSG = 2013

	mongoHeaderLength      = 20
	mongoOpCodeOffset      = 12
	mongoSectionKindLength = 1
	mongoSectionSizeLength = 4
	mongoSectionKindBody   = 0
)

func ParseMongo(payload []byte) (res string) {
	res = "<truncated>"
	if len(payload) < mongoHeaderLength+mongoSectionKindLength+mongoSectionSizeLength {
		return
	}
	opCode := binary.LittleEndian.Uint32(payload[mongoOpCodeOffset:])
	if opCode != MongoOpMSG {
		return
	}
	sectionKind := payload[mongoHeaderLength]
	if sectionKind != mongoSectionKindBody {
		return
	}
	sectionData := payload[mongoHeaderLength+mongoSectionKindLength:]
	sectionLength := binary.LittleEndian.Uint32(sectionData)
	if sectionLength < 1 || int(sectionLength) > len(sectionData) {
		return
	}
	return bson.Raw(sectionData).String()
}
