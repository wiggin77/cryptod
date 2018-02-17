package test

// GeneratePlainText generates predicable plaintext of any size.
func GeneratePlainText(size int) []byte {
	const s = "0123456789"
	src := []byte(s)
	section := make([]byte, size)

	for i := range section {
		section[i] = src[i%len(s)]
	}
	return section
}
