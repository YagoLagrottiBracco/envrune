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

func TestKDFParamsRejectsUnboundedHeaderCosts(t *testing.T) {
	for _, params := range []KDFParams{{Time: 4, MemoryKiB: 65536, Threads: 1, KeyLength: 32}, {Time: 3, MemoryKiB: 1 << 30, Threads: 1, KeyLength: 32}} {
		if params.Valid() {
			t.Fatalf("accepted unsafe parameters: %+v", params)
		}
	}
}
