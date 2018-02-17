package test

import (
	"errors"
	"io"
)

// ErrWriterFull is returned by LimitedWriter when trying to writer beyond the limit.
var ErrWriterFull = errors.New("writer full")

// LimitedWriter provides an io.Writer that can
type LimitedWriter struct {
	limit   int
	written int
	w       io.Writer
}

// NewLimitedWriter returns a new NewLimitedWriter with the specified limit.
func NewLimitedWriter(w io.Writer, limit int) *LimitedWriter {
	return &LimitedWriter{limit: limit, w: w}
}

// Write writes the bytes, returning `ErrWriterFull` if the limit is exceeded.
func (lw *LimitedWriter) Write(p []byte) (int, error) {
	if lw.written >= lw.limit {
		return 0, ErrWriterFull
	}
	avail := lw.limit - lw.written
	if avail < len(p) {
		var err error
		var n int
		if n, err = lw.w.Write(p[:avail]); err == nil {
			err = ErrWriterFull
		}
		return n, err
	}
	return lw.w.Write(p)
}
