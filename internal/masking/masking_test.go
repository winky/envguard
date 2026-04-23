package masking

import "testing"

func TestMask(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty string", "", "****"},
		{"4 chars", "abcd", "****"},
		{"8 chars", "abcdefgh", "****"},
		{"9 chars", "abcdefghi", "****fghi"},
		{"20 chars", "abcdefghijklmnopqrst", "****qrst"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Mask(tt.input)
			if got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
