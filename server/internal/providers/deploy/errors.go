package deploy

import "fmt"

// RejectedError is an explicit rejection from the remote service. A timeout,
// malformed response or server error does not prove that a write was rejected.
type RejectedError struct {
	Provider  string
	Status    int
	Message   string
	Retryable bool
}

func (e *RejectedError) Error() string {
	return fmt.Sprintf("%s rejected deployment (HTTP %d): %s", e.Provider, e.Status, e.Message)
}
func (e *RejectedError) SafeToRetry() bool        { return e.Retryable }
func (e *RejectedError) ConfirmedRejection() bool { return true }

func rejectedHTTP(provider string, status int, message string) error {
	if status >= 400 && status < 500 && status != 408 {
		return &RejectedError{Provider: provider, Status: status, Message: message, Retryable: status == 429}
	}
	return fmt.Errorf("%s returned HTTP %d: %s", provider, status, message)
}
