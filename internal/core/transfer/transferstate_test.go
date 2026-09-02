package transfer

import (
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// TestProperty28CorruptedTransfersAreAlwaysCaught covers
// Property 28: Corrupted transfers are always caught and the content is released.
//
// Validates: Requirements 7.5, 7.6
func TestProperty28CorruptedTransfersAreAlwaysCaught(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		original := rapid.SliceOfN(rapid.Byte(), 1, 200).Draw(rt, "original")
		offer := TransferOffer{
			TransferId: TransferId(rapid.StringMatching(`[a-f0-9]{8}`).Draw(rt, "transferId")),
			FileName:   "payload.bin",
			ByteSize:   int64(len(original)),
			SHA256:     DigestOf(original),
		}

		// Corrupt the content in one of the ways Property 28 names: a single changed
		// byte, a truncation, or an extension.
		corrupted := append([]byte(nil), original...)
		switch rapid.SampledFrom([]string{"flip", "truncate", "extend"}).Draw(rt, "corruption") {
		case "flip":
			at := rapid.IntRange(0, len(corrupted)-1).Draw(rt, "flipAt")
			corrupted[at] ^= byte(rapid.IntRange(1, 255).Draw(rt, "flipMask"))
		case "truncate":
			keep := rapid.IntRange(0, len(corrupted)-1).Draw(rt, "keep")
			corrupted = corrupted[:keep]
		case "extend":
			corrupted = append(corrupted,
				rapid.SliceOfN(rapid.Byte(), 1, 8).Draw(rt, "extra")...)
		}

		// Whether the receiver can release the content, which is the Req 7.5 against
		// Req 7.6 split.
		canDiscard := rapid.Bool().Draw(rt, "canDiscard")
		const retainedAt = "/tmp/peerbeam/partial-xyz"
		discardCalls := 0
		discard := func() (string, error) {
			discardCalls++
			if canDiscard {
				return "", nil
			}
			return retainedAt, errors.New("permission denied")
		}

		got := VerifyAssembled(offer, corrupted, discard)

		// A corruption always changes the digest, so it is always caught.
		if got.Verified {
			rt.Fatalf("corrupted content of %d bytes passed verification", len(corrupted))
		}
		if got.Failure == nil {
			rt.Fatal("unverified content produced no failure report")
		}
		if discardCalls != 1 {
			rt.Fatalf("discard called %d times, want once", discardCalls)
		}

		// Req 7.5: the report names the transfer identifier and both digests.
		f := got.Failure
		if f.TransferId != offer.TransferId {
			rt.Fatalf("failure names transfer %s, want %s", f.TransferId, offer.TransferId)
		}
		if hex.EncodeToString(f.OfferedDigest) != hex.EncodeToString(offer.SHA256) {
			rt.Fatal("failure does not carry the offered digest")
		}
		if hex.EncodeToString(f.ComputedDigest) != hex.EncodeToString(DigestOf(corrupted)) {
			rt.Fatal("failure does not carry the computed digest")
		}
		if hex.EncodeToString(f.OfferedDigest) == hex.EncodeToString(f.ComputedDigest) {
			rt.Fatal("failure reports two identical digests")
		}
		message := f.Error()
		for _, want := range []string{
			string(offer.TransferId),
			hex.EncodeToString(offer.SHA256),
			hex.EncodeToString(DigestOf(corrupted)),
		} {
			if !strings.Contains(message, want) {
				rt.Fatalf("report %q omits %q", message, want)
			}
		}

		// Req 7.5 discards, or Req 7.6 names where the content was retained.
		if canDiscard {
			if !f.Discarded {
				rt.Fatal("content was discardable but was reported as retained")
			}
			if f.RetainedLocation != "" {
				rt.Fatalf("discarded content reported a location %q", f.RetainedLocation)
			}
		} else {
			if f.Discarded {
				rt.Fatal("undiscardable content was reported as discarded")
			}
			if f.RetainedLocation != retainedAt {
				rt.Fatalf("retained location %q, want %q", f.RetainedLocation, retainedAt)
			}
			if f.DiscardError == "" {
				rt.Fatal("retained content carries no reason")
			}
			if !strings.Contains(message, retainedAt) {
				rt.Fatalf("report %q omits the retained location", message)
			}
		}
	})
}

// TestVerifyAssembledAcceptsFaithfulContent is the other half of Req 7.4: an intact
// transfer verifies and nothing is discarded.
//
// Requirements: 7.4
func TestVerifyAssembledAcceptsFaithfulContent(t *testing.T) {
	content := []byte("the quick brown fox")
	offer := TransferOffer{
		TransferId: "t1",
		ByteSize:   int64(len(content)),
		SHA256:     DigestOf(content),
	}

	discardCalls := 0
	got := VerifyAssembled(offer, content, func() (string, error) {
		discardCalls++
		return "", nil
	})
	if !got.Verified || got.Failure != nil {
		t.Fatalf("intact content did not verify: %+v", got)
	}
	if discardCalls != 0 {
		t.Fatal("verified content was discarded")
	}
}

// TestCheckFileSizeBoundaries pins the accepted range of Req 7.1 and 7.12, including
// the error naming both the measured size and the range.
//
// Requirements: 7.1, 7.12
func TestCheckFileSizeBoundaries(t *testing.T) {
	cases := []struct {
		name     string
		size     int64
		accepted bool
	}{
		{"zero bytes", 0, false},
		{"negative", -1, false},
		{"one byte", 1, true},
		{"one below the maximum", FileMaxBytes - 1, true},
		{"exactly 64 GiB", FileMaxBytes, true},
		{"one over 64 GiB", FileMaxBytes + 1, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CheckFileSize(c.size)
			if c.accepted {
				if got != nil {
					t.Fatalf("%d bytes rejected: %s", c.size, got.Error())
				}
				return
			}
			if got == nil {
				t.Fatalf("%d bytes accepted", c.size)
			}
			if got.MeasuredBytes != c.size {
				t.Fatalf("error names %d bytes, want %d", got.MeasuredBytes, c.size)
			}
			if got.Min != FileMinBytes || got.Max != FileMaxBytes {
				t.Fatalf("error names range %d..%d, want %d..%d",
					got.Min, got.Max, FileMinBytes, FileMaxBytes)
			}
			message := got.Error()
			for _, want := range []string{
				strconv.FormatInt(c.size, 10),
				strconv.FormatInt(FileMaxBytes, 10),
			} {
				if !strings.Contains(message, want) {
					t.Fatalf("error %q omits %q", message, want)
				}
			}
		})
	}
}

// TestProgressReportCarriesEverythingRequired pins the four values Req 7.3 requires.
//
// Requirements: 7.3
func TestProgressReportCarriesEverythingRequired(t *testing.T) {
	p := NewTransferProgress(1000)
	p.OnAck(0, 250)

	got := p.Report("tx-9", 41_943_040)
	if got.TransferId != "tx-9" {
		t.Fatalf("report names transfer %s", got.TransferId)
	}
	if got.AcknowledgedBytes != 250 {
		t.Fatalf("report says %d bytes acknowledged, want 250", got.AcknowledgedBytes)
	}
	if got.TotalBytes != 1000 {
		t.Fatalf("report says total %d, want 1000", got.TotalBytes)
	}
	if got.GoodputBytesPerSecond != 41_943_040 {
		t.Fatalf("report says goodput %d", got.GoodputBytesPerSecond)
	}
	for _, want := range []string{"tx-9", "250", "1000", "41943040"} {
		if !strings.Contains(got.String(), want) {
			t.Fatalf("rendered report %q omits %q", got.String(), want)
		}
	}
}

// TestNewTransferIdIsDistinctAndHex pins the identifier shape.
//
// Requirements: 7.1
func TestNewTransferIdIsDistinctAndHex(t *testing.T) {
	seen := map[TransferId]struct{}{}
	for i := 0; i < 128; i++ {
		id, err := NewTransferId()
		if err != nil {
			t.Fatalf("NewTransferId: %v", err)
		}
		if len(id) != TransferIdBytes*2 {
			t.Fatalf("id %q is %d chars, want %d", id, len(id), TransferIdBytes*2)
		}
		if strings.Trim(string(id), "0123456789abcdef") != "" {
			t.Fatalf("id %q is not lowercase hex", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("id %q generated twice", id)
		}
		seen[id] = struct{}{}
	}
}

// TestOfferOutcomeGatesChunkSending checks that only an accepted offer permits Chunks,
// which is the shared core of Req 7.11 and 7.12.
//
// Requirements: 7.11, 7.12
func TestOfferOutcomeGatesChunkSending(t *testing.T) {
	cases := map[string]OfferOutcome{
		"accepted":  {Accepted: true},
		"declined":  {Declined: true},
		"timed out": {TimedOut: true},
		"bad size":  {Unsupported: &UnsupportedFileSize{MeasuredBytes: 0, Min: FileMinBytes, Max: FileMaxBytes}},
	}
	for name, outcome := range cases {
		t.Run(name, func(t *testing.T) {
			if outcome.MaySendChunks() != outcome.Accepted {
				t.Fatalf("%s permits chunks: %v", name, outcome.MaySendChunks())
			}
			if outcome.Accepted {
				if outcome.Reason() != "" {
					t.Fatalf("accepted offer carries reason %q", outcome.Reason())
				}
				return
			}
			if outcome.Reason() == "" {
				t.Fatalf("%s carries no reason", name)
			}
		})
	}

	// Req 7.11: the timeout reason names the 60-second window.
	timedOut := OfferOutcome{TimedOut: true}
	if !strings.Contains(timedOut.Reason(), "1m0s") {
		t.Fatalf("timeout reason %q does not name the window", timedOut.Reason())
	}
	if OfferTimeout != 60*time.Second {
		t.Fatalf("offer timeout is %s, want 60s", OfferTimeout)
	}
}
