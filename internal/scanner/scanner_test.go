package scanner

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/cquark7/withhold/internal/detector"
)

// Profile warm inspection separately from transport and child initialization.
func BenchmarkScan(b *testing.B) {
	d, err := detector.New("")
	if err != nil {
		b.Fatal(err)
	}
	s := New(d, func() []byte { return []byte("isolated-benchmark-only") })
	for _, kind := range []string{"clean", "redacted"} {
		for _, size := range []int{2048, 128 * 1024, 1024 * 1024} {
			b.Run(kind+"/"+strconv.Itoa(size), func(b *testing.B) {
				text := strings.Repeat("Explain this function and suggest a clearer name.\n", size/48+1)[:size]
				if kind == "redacted" {
					text += "\ntoken = \"sk_live_4eC39HqLyjWDarjtT1zdp7dc\"\n"
				}
				body, err := json.Marshal(map[string]string{"input": text})
				if err != nil {
					b.Fatal(err)
				}
				b.SetBytes(int64(len(body)))
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					if report := s.Scan(body, DefaultMaxBytes); report["status"] != kind {
						b.Fatalf("unexpected scan status: %v", report["status"])
					}
				}
			})
		}
	}
}
