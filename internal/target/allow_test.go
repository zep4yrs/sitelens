package target

import "testing"

func TestAllowed(t *testing.T) {
	cases := []struct {
		host  string
		allow []string
		want  bool
	}{
		{"example.com", nil, true},
		{"example.com", []string{}, true},
		{"example.com", []string{"example.com"}, true},
		{"EXAMPLE.com", []string{"example.com"}, true},
		{"example.com.", []string{"example.com"}, true},
		{"a.example.com", []string{"*.example.com"}, true},
		{"example.com", []string{"*.example.com"}, false},
		{"badexample.com", []string{"*.example.com"}, false},
		{"other.com", []string{"example.com", "*.test.com"}, false},
		{"x.test.com", []string{"example.com", "*.test.com"}, true},
		{"", []string{"example.com"}, false},
		{"example.com", []string{"  ", "example.com"}, true},
	}
	for _, c := range cases {
		if got := Allowed(c.host, c.allow); got != c.want {
			t.Fatalf("Allowed(%q, %v)=%v want %v", c.host, c.allow, got, c.want)
		}
	}
}
