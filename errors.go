package httpsignatures

import "fmt"

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
