package convert_test

import (
	"testing"

	"github.com/a-rodian-jedi/neutrino/internal/convert"
)

func TestInt8SliceToString(t *testing.T) {
	tests := []struct {
		name  string
		input []int8
		want  string
	}{
		{
			name:  "normal null-terminated string",
			input: []int8{'c', 'u', 'r', 'l', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			want:  "curl",
		},
		{
			name:  "full buffer no null byte",
			input: []int8{'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p'},
			want:  "abcdefghijklmnop",
		},
		{
			name:  "empty string null at position zero",
			input: []int8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			want:  "",
		},
		{
			name:  "null in the middle",
			input: []int8{'b', 'a', 's', 'h', 0, 'j', 'u', 'n', 'k', 0, 0, 0, 0, 0, 0, 0},
			want:  "bash",
		},
		{
			name:  "single character",
			input: []int8{'x', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			want:  "x",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := convert.Int8SliceToString(tt.input)
			if got != tt.want {
				t.Errorf("Int8SliceToString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func BenchmarkInt8SliceToString(b *testing.B) {
	// Simulates a typical 16-byte comm field with a short command name
	input := [16]int8{'c', 'u', 'r', 'l', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	b.ReportAllocs()
	for b.Loop() {
		_ = convert.Int8SliceToString(input[:])
	}
}
