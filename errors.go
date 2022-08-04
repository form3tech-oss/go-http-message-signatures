package httpsignatures

import "fmt"

// HashingErrors is an error encountered when attempting to hash content.
type HashingError struct {
	message string
	err     error
}

func NewHashingError(message string, err error) *HashingError {
	return &HashingError{
		message: message,
		err:     err,
	}
}

func (he *HashingError) Error() string {
	return fmt.Sprintf("%s: %s", he.message, he.err)
}

func (he *HashingError) Unwrap() error {
	return he.err
}

// SigningError is an error encountered when attempting to sign content.
type SigningError struct {
	message string
	err     error
}

func NewSigningError(message string, err error) *SigningError {
	return &SigningError{
		message: message,
		err:     err,
	}
}

func (se *SigningError) Error() string {
	return fmt.Sprintf("%s: %s", se.message, se.err)
}

func (se *SigningError) Unwrap() error {
	return se.err
}

// ValidationError is an error encountered when attempting to validate input data.
type ValidationError struct {
	message string
}

func NewValidationError(message string) *ValidationError {
	return &ValidationError{
		message: message,
	}
}

func (ve *ValidationError) Error() string {
	return ve.message
}

// DataError is an error encountered when input data does not contain the correct
// content or an error is raised attempting to read the data.
type DataError struct {
	message string
	err     error
}

func NewDataError(message string, err error) *DataError {
	return &DataError{
		message: message,
		err:     err,
	}
}

func (de *DataError) Error() string {
	return fmt.Sprintf("%s: %s", de.message, de.err)
}

func (de *DataError) Unwrap() error {
	return de.err
}

// InitialisationError is an error encountered when we fail to initialise a new object.
type InitialisationError struct {
	message string
	err     error
}

func NewInitialisationError(message string, err error) *InitialisationError {
	return &InitialisationError{
		message: message,
		err:     err,
	}
}

func (ie *InitialisationError) Error() string {
	return fmt.Sprintf("%s: %s", ie.message, ie.err)
}

func (ie *InitialisationError) Unwrap() error {
	return ie.err
}

// InternalError is an error that the user can't fix themselves. Such as an error encountered
// closing a request body.
type InternalError struct {
	message string
	err     error
}

func NewInternalError(message string, err error) *InternalError {
	return &InternalError{
		message: message,
		err:     err,
	}
}

func (ie *InternalError) Error() string {
	return fmt.Sprintf("%s: %s", ie.message, ie.err)
}

func (ie *InternalError) Unwrap() error {
	return ie.err
}

type VerificationError struct {
	message string
	err     error
}

func NewVerificationError(message string, err error) *VerificationError {
	return &VerificationError{
		message: message,
		err:     err,
	}
}
func (ve *VerificationError) Error() string {
	return fmt.Sprintf("%s: %s", ve.message, ve.err)
}

func (ve *VerificationError) Unwrap() error {
	return ve.err
}

type SignatureError struct {
	message string
	err     error
}

func NewSignatureError(message string, err error) *SignatureError {
	return &SignatureError{
		message: message,
		err:     err,
	}
}

func (se *SignatureError) Error() string {
	return fmt.Sprintf("%s: %s", se.message, se.err)
}

func (se *SignatureError) Unwrap() error {
	return se.err
}
