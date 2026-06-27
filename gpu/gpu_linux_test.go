//go:build linux

package gpu

import (
	"encoding/binary"
	"math"
	"testing"
)

func TestValueToFloat(t *testing.T) {
	var unsignedInt [8]byte
	binary.LittleEndian.PutUint32(unsignedInt[:], 42)
	got, err := valueToFloat(nvmlValueTypeUnsignedInt, unsignedInt)
	if err != nil {
		t.Fatal(err)
	}
	if got != 42 {
		t.Fatalf("unsigned int value = %v, want 42", got)
	}

	var signedInt [8]byte
	signedValue := int32(-7)
	binary.LittleEndian.PutUint32(signedInt[:], uint32(signedValue))
	got, err = valueToFloat(nvmlValueTypeSignedInt, signedInt)
	if err != nil {
		t.Fatal(err)
	}
	if got != -7 {
		t.Fatalf("signed int value = %v, want -7", got)
	}

	var double [8]byte
	binary.LittleEndian.PutUint64(double[:], math.Float64bits(12.5))
	got, err = valueToFloat(nvmlValueTypeDouble, double)
	if err != nil {
		t.Fatal(err)
	}
	if got != 12.5 {
		t.Fatalf("double value = %v, want 12.5", got)
	}
}
