package node

import "testing"

func TestIsDialLiteral(t *testing.T) {
	tests := []struct {
		ref  string
		want bool
	}{
		{"192.168.40.5:4748", true},   // ip:port
		{"10.0.0.1:4748", true},       // ip:port
		{"192.168.40.5", true},        // bare ip
		{"10.0.0.1", true},            // bare ip
		{"alice", false},              // alias
		{"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d", false}, // hex peer id
		{"", false},                   // empty
		{":4748", true},               // weird but colon wins
	}
	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			if got := isDialLiteral(tt.ref); got != tt.want {
				t.Errorf("isDialLiteral(%q) = %v, want %v", tt.ref, got, tt.want)
			}
		})
	}
}
