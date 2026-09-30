// Package runner owns the short-lived environment passed to child processes.
package runner

// Pair is one environment assignment. Value must be wiped by its final consumer.
type Pair struct {
	Name  string
	Value []byte
}
