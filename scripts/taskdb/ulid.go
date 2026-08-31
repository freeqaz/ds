// SPDX-License-Identifier: Apache-2.0
package main

import (
	"crypto/rand"
	"time"
)

// Crockford base32 alphabet (no I, L, O, U — avoids visual ambiguity).
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// newID returns a ULID: a 26-character Crockford base32 string encoding a
// 48-bit millisecond timestamp followed by 80 bits of randomness. ULIDs sort
// lexicographically by creation time and are case-insensitive, so a short
// prefix is a stable handle (see resolveTaskID).
func newID() string {
	ms := uint64(time.Now().UnixMilli()) & ((1 << 48) - 1)
	var ent [10]byte
	rand.Read(ent[:])
	return encodeULID(ms, ent)
}

// encodeULID lays out the canonical ULID bit pattern: 48-bit timestamp across
// the first 10 characters, 80-bit entropy across the remaining 16.
func encodeULID(ms uint64, e [10]byte) string {
	d := make([]byte, 26)
	d[0] = crockford[(ms>>45)&0x1f]
	d[1] = crockford[(ms>>40)&0x1f]
	d[2] = crockford[(ms>>35)&0x1f]
	d[3] = crockford[(ms>>30)&0x1f]
	d[4] = crockford[(ms>>25)&0x1f]
	d[5] = crockford[(ms>>20)&0x1f]
	d[6] = crockford[(ms>>15)&0x1f]
	d[7] = crockford[(ms>>10)&0x1f]
	d[8] = crockford[(ms>>5)&0x1f]
	d[9] = crockford[ms&0x1f]
	d[10] = crockford[(e[0]&0xf8)>>3]
	d[11] = crockford[((e[0]&0x07)<<2)|((e[1]&0xc0)>>6)]
	d[12] = crockford[(e[1]&0x3e)>>1]
	d[13] = crockford[((e[1]&0x01)<<4)|((e[2]&0xf0)>>4)]
	d[14] = crockford[((e[2]&0x0f)<<1)|((e[3]&0x80)>>7)]
	d[15] = crockford[(e[3]&0x7c)>>2]
	d[16] = crockford[((e[3]&0x03)<<3)|((e[4]&0xe0)>>5)]
	d[17] = crockford[e[4]&0x1f]
	d[18] = crockford[(e[5]&0xf8)>>3]
	d[19] = crockford[((e[5]&0x07)<<2)|((e[6]&0xc0)>>6)]
	d[20] = crockford[(e[6]&0x3e)>>1]
	d[21] = crockford[((e[6]&0x01)<<4)|((e[7]&0xf0)>>4)]
	d[22] = crockford[((e[7]&0x0f)<<1)|((e[8]&0x80)>>7)]
	d[23] = crockford[(e[8]&0x7c)>>2]
	d[24] = crockford[((e[8]&0x03)<<3)|((e[9]&0xe0)>>5)]
	d[25] = crockford[e[9]&0x1f]
	return string(d)
}
