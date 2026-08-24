package flate

import (
	"bytes"
	"io"
	"os"
	"runtime"
	"testing"
)

// genericOnly hides every concrete type huffmanBlockDecoder dispatches on, so
// decoding goes through huffmanGenericReader as a reference implementation.
type genericOnly struct{ r *bytes.Reader }

func (g genericOnly) Read(p []byte) (int, error) { return g.r.Read(p) }
func (g genericOnly) ReadByte() (byte, error)    { return g.r.ReadByte() }

// roundtripBytesBuffer round-trips data through a *bytes.Buffer source (the
// hand-written huffmanBytesBuffer decoder in inflate_bytesbuffer.go),
// asserting byte-for-byte equality against the input and identical behavior to
// the generic reader path. The small copy buffers force window flushes, which
// exercise the over-read rewind and Next-based position sync at every return.
func roundtripBytesBuffer(t *testing.T, data []byte) {
	t.Helper()
	for _, lvl := range []int{0, 1, 6, 9} {
		var comp bytes.Buffer
		w, err := NewWriter(&comp, lvl)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		c := comp.Bytes()
		for name, sz := range map[string]int{"readall": 0, "small": 1024, "tiny": 1} {
			if sz == 1 && len(data) > 64<<10 {
				// The window-flush sync paths this pass exercises fire per
				// 32 KiB flush, not per byte; huge inputs only slow the fuzzer.
				continue
			}
			got, err := readWithBuffer(NewReader(bytes.NewBuffer(c)), sz)
			if err != nil {
				t.Fatalf("level %d, %s: %v", lvl, name, err)
			}
			if !bytes.Equal(got, data) {
				t.Fatalf("level %d, %s: round-trip mismatch (%d vs %d bytes)", lvl, name, len(got), len(data))
			}
		}
	}
}

func readWithBuffer(r io.Reader, bufSize int) ([]byte, error) {
	if bufSize == 0 {
		return io.ReadAll(r)
	}
	var out bytes.Buffer
	_, err := io.CopyBuffer(&out, struct{ io.Reader }{r}, make([]byte, bufSize))
	return out.Bytes(), err
}

// testBytesBufferMatchesGeneric feeds arbitrary (including corrupt) compressed
// bytes to both the *bytes.Buffer decoder and the generic reader decoder and
// requires the same output and the same success/failure outcome.
func testBytesBufferMatchesGeneric(t *testing.T, comp []byte) {
	t.Helper()
	wantData, wantErr := io.ReadAll(NewReader(genericOnly{bytes.NewReader(comp)}))
	gotData, gotErr := io.ReadAll(NewReader(bytes.NewBuffer(comp)))
	if (wantErr == nil) != (gotErr == nil) {
		t.Fatalf("error mismatch: generic=%v bytesbuffer=%v", wantErr, gotErr)
	}
	if !bytes.Equal(wantData, gotData) {
		t.Fatalf("output mismatch: generic=%d bytes, bytesbuffer=%d bytes", len(wantData), len(gotData))
	}
}

func TestInflateBytesBufferCorrupt(t *testing.T) {
	var comp bytes.Buffer
	w, err := NewWriter(&comp, 6)
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("the quick brown fox jumps over the lazy dog "), 3000)
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	c := comp.Bytes()
	testBytesBufferMatchesGeneric(t, c)
	// Truncations, including inside the trailing 8 bytes where the fast path
	// falls back to byte-at-a-time refills.
	for _, cut := range []int{1, 2, 7, 8, 9, len(c) / 2, len(c) - 1} {
		if cut < len(c) {
			testBytesBufferMatchesGeneric(t, c[:len(c)-cut])
		}
	}
	// Single-byte corruptions sprinkled through the stream.
	for i := 0; i < len(c); i += 251 {
		mut := bytes.Clone(c)
		mut[i] ^= 0x5a
		testBytesBufferMatchesGeneric(t, mut)
	}
}

func FuzzInflateBytesBuffer(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("a"))
	f.Add(bytes.Repeat([]byte("hello world "), 5000))
	f.Add(bytes.Repeat([]byte{0}, 100000))
	seq := make([]byte, 20000)
	for i := range seq {
		seq[i] = byte(i*31 + i/7)
	}
	f.Add(seq)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<18 { // keep fuzz execs fast; larger inputs add no new paths here
			return
		}
		roundtripBytesBuffer(t, data)
		// Also treat the input as a (usually corrupt) compressed stream and
		// require behavior identical to the generic reader path.
		testBytesBufferMatchesGeneric(t, data)
	})
}

// benchmarkDecodeBytesBuffer mirrors benchmarkDecode but decodes from a
// *bytes.Buffer, exercising the fast decoder in inflate_bytesbuffer.go.
func benchmarkDecodeBytesBuffer(b *testing.B, testfile, level, n int) {
	b.ReportAllocs()
	b.StopTimer()
	b.SetBytes(int64(n))
	buf0, err := os.ReadFile(testfiles[testfile])
	if err != nil {
		b.Fatal(err)
	}
	if len(buf0) == 0 {
		b.Fatalf("test file %q has no data", testfiles[testfile])
	}
	compressed := new(bytes.Buffer)
	w, err := NewWriter(compressed, level)
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < n; i += len(buf0) {
		if len(buf0) > n-i {
			buf0 = buf0[:n-i]
		}
		io.Copy(w, bytes.NewReader(buf0))
	}
	w.Close()
	buf1 := compressed.Bytes()
	buf0, compressed, w = nil, nil, nil
	r := NewReader(bytes.NewBuffer(buf1))
	res := r.(Resetter)
	runtime.GC()
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		_ = res.Reset(bytes.NewBuffer(buf1), nil)
		_, _ = io.Copy(io.Discard, r)
	}
}

func BenchmarkDecodeBytesBufferDigitsDefault1e5(b *testing.B) {
	benchmarkDecodeBytesBuffer(b, digits, default_, 1e5)
}
func BenchmarkDecodeBytesBufferDigitsDefault1e6(b *testing.B) {
	benchmarkDecodeBytesBuffer(b, digits, default_, 1e6)
}
func BenchmarkDecodeBytesBufferTwainDefault1e5(b *testing.B) {
	benchmarkDecodeBytesBuffer(b, twain, default_, 1e5)
}
func BenchmarkDecodeBytesBufferTwainDefault1e6(b *testing.B) {
	benchmarkDecodeBytesBuffer(b, twain, default_, 1e6)
}
