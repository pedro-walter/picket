// Package vsort compares version-like strings the way GNU `sort -V` does:
// maximal digit runs compare numerically, other runs byte-by-byte. Enough
// for container tags ("16.14-alpine", "v3.7.1", "0.57.0-alpine"); no tilde
// handling (tags do not use it).
package vsort

// Less reports whether a orders before b.
func Less(a, b string) bool { return cmp(a, b) < 0 }

func cmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if isDigit(a[i]) && isDigit(b[j]) {
			is, js := i, j
			for i < len(a) && isDigit(a[i]) {
				i++
			}
			for j < len(b) && isDigit(b[j]) {
				j++
			}
			na := trimLeadingZeros(a[is:i])
			nb := trimLeadingZeros(b[js:j])
			if len(na) != len(nb) {
				if len(na) < len(nb) {
					return -1
				}
				return 1
			}
			if na != nb {
				if na < nb {
					return -1
				}
				return 1
			}
			// equal numeric value: shorter original (fewer leading zeros) first
			if (i - is) != (j - js) {
				if (i - is) < (j - js) {
					return -1
				}
				return 1
			}
		} else {
			if a[i] != b[j] {
				if a[i] < b[j] {
					return -1
				}
				return 1
			}
			i++
			j++
		}
	}
	switch {
	case i < len(a):
		return 1
	case j < len(b):
		return -1
	default:
		return 0
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func trimLeadingZeros(s string) string {
	for len(s) > 1 && s[0] == '0' {
		s = s[1:]
	}
	return s
}
