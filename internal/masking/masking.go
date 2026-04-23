package masking

// Mask masks a credential value.
// For values of 8 characters or fewer, returns "****".
// For values of 9 characters or more, returns "****" followed by the last 4 characters.
func Mask(value string) string {
	if len(value) <= 8 {
		return "****"
	}
	return "****" + value[len(value)-4:]
}
