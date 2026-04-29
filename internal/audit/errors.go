package audit

import "errors"

// Sentinel errors shared across the audit package.
var (
	// ErrNilScanner is returned when a nil *Scanner is provided where one is required.
	ErrNilScanner = errors.New("audit: scanner must not be nil")

	// ErrNilCallback is returned when a nil callback function is provided.
	ErrNilCallback = errors.New("audit: callback must not be nil")

	// ErrInvalidPage is returned when a page number less than 1 is requested.
	ErrInvalidPage = errors.New("audit: page number must be >= 1")

	// ErrInvalidPageSize is returned when a page size less than 1 is requested.
	ErrInvalidPageSize = errors.New("audit: page size must be >= 1")

	// ErrNilReport is returned when a nil *Report is provided where one is required.
	ErrNilReport = errors.New("audit: report must not be nil")
)
