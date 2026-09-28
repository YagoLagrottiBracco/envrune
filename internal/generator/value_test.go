package generator

import "testing"

func TestNewProducesRequestedLengthAndDistinctValues(t *testing.T) {
	first, err := New(32)
	if err != nil { t.Fatal(err) }
	second, err := New(32)
	if err != nil { t.Fatal(err) }
	if len(first) != 32 || len(second) != 32 { t.Fatalf("unexpected lengths: %d, %d", len(first), len(second)) }
	if string(first) == string(second) { t.Fatal("generated values unexpectedly matched") }
}

func TestNewRejectsUnsafeLengths(t *testing.T) {
	for _, length := range []int{0, -1, 4097} { if _, err := New(length); err == nil { t.Fatalf("New(%d) unexpectedly succeeded", length) } }
}
