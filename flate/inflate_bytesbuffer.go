package flate

import (
	"bytes"
	"fmt"
	"io"
	"math/bits"

	"github.com/klauspost/compress/internal/le"
	"github.com/klauspost/compress/internal/regmask"
)

// syncBytesBuffer publishes the local decode state back to the decompressor
// and the source buffer on exit: whole unconsumed bytes are rewound — never
// more than were taken from the buffer in this call, since the bit buffer can
// also hold bits that predate it, which stay in f.b — the sub-byte remainder
// is masked into f.b/f.nb, and only consumed bytes are drained from fr.
func (f *decompressor) syncBytesBuffer(fr *bytes.Buffer, pos int, fb uint64, fnb uint) {
	k := min(int(fnb>>3), pos)
	pos -= k
	fnb -= uint(k) << 3
	f.b = uint32(fb & (1<<(fnb&regmask.Shift64ByUint) - 1))
	f.nb = fnb
	fr.Next(pos)
	f.roffset += int64(pos)
}

// huffmanBytesBuffer decodes a single Huffman block from f when the input is a
// *bytes.Buffer, meaning the remaining compressed input is available up front
// as a slice via Bytes().
//
// Unlike the generated readers in inflate_gen.go, which pull input one byte at
// a time into a 32-bit bit buffer, this decoder keeps a 64-bit bit buffer and
// refills it with a single 8-byte little-endian load per symbol. After one
// refill the buffer holds at least 56 bits, which covers a worst-case
// literal/length code (15 bits), length extra bits (5), distance code (15) and
// distance extra bits (13) without checking for input again. The per-bit-need
// refill loops below only run within the last 8 bytes of input.
//
// The bit buffer over-reads bytes it may not consume (up to 7), so every exit
// returns whole unconsumed bytes before syncing the buffer: only consumed
// bytes are drained with Next, and f.b/f.nb keep the sub-byte remainder,
// preserving the invariants the rest of the decompressor relies on.
func (f *decompressor) huffmanBytesBuffer() {
	const (
		stateInit = iota // Zero value must be stateInit
		stateDict
	)
	fr := f.r.(*bytes.Buffer)
	pbuf := fr.Bytes()
	pos := 0

	// Optimization. Compiler isn't smart enough to keep f.b,f.nb in registers,
	// but is smart enough to keep local variables in registers, so use nb and b,
	// inline refills and reassign b,nb back to f on return.
	fnb, dict := f.nb, &f.dict
	fb := uint64(f.b)

	switch f.stepState {
	case stateInit:
		goto readLiteral
	case stateDict:
		goto copyHistory
	}

readLiteral:
	// Read literal and/or (length, distance) according to RFC section 3.2.3.
	{
		// One refill covers the whole iteration (see the function comment).
		if fnb < 56 {
			if pos+8 <= len(pbuf) {
				x := le.Load64(pbuf, pos)
				fb |= x << (fnb & regmask.Shift64ByUint)
				n := (63 - fnb) >> 3
				pos += int(n)
				fnb += n << 3
			} else {
				for fnb < 56 && pos < len(pbuf) {
					fb |= uint64(pbuf[pos]) << (fnb & regmask.Shift64ByUint)
					pos++
					fnb += 8
				}
			}
		}

		var v int
		{
			// Inlined v, err := f.huffSym(f.hl)
			// Since a huffmanDecoder can be empty or be composed of a degenerate tree
			// with single element, huffSym must error on these two edge cases. In both
			// cases, the chunks slice will be 0 for the invalid sequence, leading it
			// satisfy the n == 0 check below.
			n := uint(f.hl.maxRead)
			for {
				for fnb < n {
					if pos >= len(pbuf) {
						f.syncBytesBuffer(fr, pos, fb, fnb)
						f.err = noEOF(io.EOF)
						return
					}
					fb |= uint64(pbuf[pos]) << (fnb & regmask.Shift64ByUint)
					pos++
					fnb += 8
				}
				chunk := f.hl.chunks[uint32(fb)&(huffmanNumChunks-1)]
				n = uint(chunk & huffmanCountMask)
				if n > huffmanChunkBits {
					chunk = f.hl.links[chunk>>huffmanValueShift][(uint32(fb)>>huffmanChunkBits)&f.hl.linkMask]
					n = uint(chunk & huffmanCountMask)
				}
				if n <= fnb {
					if n == 0 {
						f.syncBytesBuffer(fr, pos, fb, fnb)
						if debugDecode {
							fmt.Println("huffsym: n==0")
						}
						f.err = CorruptInputError(f.roffset)
						return
					}
					fb = fb >> (n & regmask.Shift64ByUint)
					fnb = fnb - n
					v = int(chunk >> huffmanValueShift)
					break
				}
			}
		}

		var length int
		switch {
		case v < 256:
			dict.writeByte(byte(v))
			if dict.availWrite() == 0 {
				f.syncBytesBuffer(fr, pos, fb, fnb)
				f.toRead = dict.readFlush()
				f.step = huffmanBytesBuffer
				f.stepState = stateInit
				return
			}
			goto readLiteral
		case v == 256:
			f.syncBytesBuffer(fr, pos, fb, fnb)
			f.finishBlock()
			return
		// otherwise, reference to older data
		case v < 265:
			length = v - (257 - 3)
		case v < maxNumLit:
			val := decCodeToLen[(v - 257)]
			length = int(val.length) + 3
			n := uint(val.extra)
			for fnb < n {
				if pos >= len(pbuf) {
					f.syncBytesBuffer(fr, pos, fb, fnb)
					if debugDecode {
						fmt.Println("morebits n>0: EOF")
					}
					f.err = noEOF(io.EOF)
					return
				}
				fb |= uint64(pbuf[pos]) << (fnb & regmask.Shift64ByUint)
				pos++
				fnb += 8
			}
			length += int(uint32(fb) & bitMask32[n])
			fb >>= n & regmask.Shift64ByUint
			fnb -= n
		default:
			if debugDecode {
				fmt.Println(v, ">= maxNumLit")
			}
			f.syncBytesBuffer(fr, pos, fb, fnb)
			f.err = CorruptInputError(f.roffset)
			return
		}

		var dist uint32
		if f.hd == nil {
			for fnb < 5 {
				if pos >= len(pbuf) {
					f.syncBytesBuffer(fr, pos, fb, fnb)
					if debugDecode {
						fmt.Println("morebits f.nb<5: EOF")
					}
					f.err = noEOF(io.EOF)
					return
				}
				fb |= uint64(pbuf[pos]) << (fnb & regmask.Shift64ByUint)
				pos++
				fnb += 8
			}
			dist = uint32(bits.Reverse8(uint8(fb & 0x1F << 3)))
			fb >>= 5
			fnb -= 5
		} else {
			// Since a huffmanDecoder can be empty or be composed of a degenerate tree
			// with single element, huffSym must error on these two edge cases. In both
			// cases, the chunks slice will be 0 for the invalid sequence, leading it
			// satisfy the n == 0 check below.
			n := uint(f.hd.maxRead)
			for {
				for fnb < n {
					if pos >= len(pbuf) {
						f.syncBytesBuffer(fr, pos, fb, fnb)
						f.err = noEOF(io.EOF)
						return
					}
					fb |= uint64(pbuf[pos]) << (fnb & regmask.Shift64ByUint)
					pos++
					fnb += 8
				}
				chunk := f.hd.chunks[uint32(fb)&(huffmanNumChunks-1)]
				n = uint(chunk & huffmanCountMask)
				if n > huffmanChunkBits {
					chunk = f.hd.links[chunk>>huffmanValueShift][(uint32(fb)>>huffmanChunkBits)&f.hd.linkMask]
					n = uint(chunk & huffmanCountMask)
				}
				if n <= fnb {
					if n == 0 {
						f.syncBytesBuffer(fr, pos, fb, fnb)
						if debugDecode {
							fmt.Println("huffsym: n==0")
						}
						f.err = CorruptInputError(f.roffset)
						return
					}
					fb = fb >> (n & regmask.Shift64ByUint)
					fnb = fnb - n
					dist = uint32(chunk >> huffmanValueShift)
					break
				}
			}
		}

		switch {
		case dist < 4:
			dist++
		case dist < maxNumDist:
			nb := uint(dist-2) >> 1
			// have 1 bit in bottom of dist, need nb more.
			extra := (dist & 1) << (nb & regmask.Shift32ByUint)
			for fnb < nb {
				if pos >= len(pbuf) {
					f.syncBytesBuffer(fr, pos, fb, fnb)
					if debugDecode {
						fmt.Println("morebits f.nb<nb: EOF")
					}
					f.err = noEOF(io.EOF)
					return
				}
				fb |= uint64(pbuf[pos]) << (fnb & regmask.Shift64ByUint)
				pos++
				fnb += 8
			}
			extra |= uint32(fb) & bitMask32[nb]
			fb >>= nb & regmask.Shift64ByUint
			fnb -= nb
			dist = 1<<((nb+1)&regmask.Shift32ByUint) + 1 + extra
			// slower: dist = bitMask32[nb+1] + 2 + extra
		default:
			f.syncBytesBuffer(fr, pos, fb, fnb)
			if debugDecode {
				fmt.Println("dist too big:", dist, maxNumDist)
			}
			f.err = CorruptInputError(f.roffset)
			return
		}

		// No check on length; encoding can be prescient.
		if dist > uint32(dict.histSize()) {
			f.syncBytesBuffer(fr, pos, fb, fnb)
			if debugDecode {
				fmt.Println("dist > dict.histSize():", dist, dict.histSize())
			}
			f.err = CorruptInputError(f.roffset)
			return
		}

		f.copyLen, f.copyDist = length, int(dist)
		goto copyHistory
	}

copyHistory:
	// Perform a backwards copy according to RFC section 3.2.3.
	{
		cnt := dict.tryWriteCopy(f.copyDist, f.copyLen)
		if cnt == 0 {
			cnt = dict.writeCopy(f.copyDist, f.copyLen)
		}
		f.copyLen -= cnt

		if dict.availWrite() == 0 || f.copyLen > 0 {
			f.syncBytesBuffer(fr, pos, fb, fnb)
			f.toRead = dict.readFlush()
			f.step = huffmanBytesBuffer // We need to continue this work
			f.stepState = stateDict
			return
		}
		goto readLiteral
	}
	// Not reached
}
