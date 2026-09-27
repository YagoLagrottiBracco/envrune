package crypto

import "testing"

func TestDefaultKDFParamsUsesSecondRFC9106Profile(t *testing.T) {
	params := DefaultKDFParams(16)
	if params.Time != 3 || params.MemoryKiB != 65536 || params.Threads != 4 || params.KeyLength != 32 {
		t.Fatalf("unexpected parameters: %+v", params)
	}
}

func TestDefaultKDFParamsUsesAtLeastOneThread(t *testing.T) {
	if got := DefaultKDFParams(0).Threads; got != 1 {
		t.Fatalf("Threads = %d, want 1", got)
	}
}
