package verify

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

// The point of this file is one comparison: Go's crypto/sha256 uses the ARMv8
// SHA-2 instructions, and sentinel-core's hand-rolled implementation does not.
// The ratio is the measured price of the zero-dependency decision, and it
// belongs in bench/results.md next to the Rust numbers rather than being
// hand-waved as "probably slower".
func BenchmarkStdlibSHA256(b *testing.B) {
	for _, size := range []int{32, 256, 4096, 1 << 20} {
		data := make([]byte, size)
		for i := range data {
			data[i] = 0x5a
		}
		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			for i := 0; i < b.N; i++ {
				_ = sha256.Sum256(data)
			}
		})
	}
}

// Verification cost in Go, for comparison with the Rust verifier. An auditor
// runs this one, so its throughput is what determines whether auditing a
// large log end to end is practical.
func BenchmarkInclusionVerify(b *testing.B) {
	const size = 1 << 20
	leaves := make([]Hash, size)
	for i := range leaves {
		leaves[i] = HashLeaf([]byte(fmt.Sprintf("leaf-%d", i)))
	}
	root := referenceRoot(leaves)

	// Pre-generate so proof construction is not folded into the measurement.
	const cases = 2048
	type c struct {
		index uint64
		proof []Hash
		leaf  Hash
	}
	prepared := make([]c, cases)
	for i := range prepared {
		idx := uint64(i*7919) % size
		prepared[i] = c{idx, referenceInclusion(leaves, idx), leaves[idx]}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := prepared[i%cases]
		if err := Inclusion(p.index, size, p.leaf, p.proof, root); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkConsistencyVerify(b *testing.B) {
	const size = 1 << 20
	leaves := make([]Hash, size)
	for i := range leaves {
		leaves[i] = HashLeaf([]byte(fmt.Sprintf("leaf-%d", i)))
	}
	root := referenceRoot(leaves)

	const cases = 512
	type c struct {
		first     uint64
		proof     []Hash
		firstRoot Hash
	}
	prepared := make([]c, cases)
	for i := range prepared {
		first := uint64(i*193)%size + 1
		prepared[i] = c{first, referenceConsistency(leaves[:size], first), referenceRoot(leaves[:first])}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := prepared[i%cases]
		if err := Consistency(p.first, size, p.firstRoot, root, p.proof); err != nil {
			b.Fatal(err)
		}
	}
}
