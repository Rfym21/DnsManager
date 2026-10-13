package cert

// UnknownError prevents a lost response from being treated as permission to
// create another remote certificate order.
type UnknownError struct{ Message string }

func (e *UnknownError) Error() string       { return e.Message }
func (e *UnknownError) UnknownResult() bool { return true }

type RejectedError struct{ Message string }

func (e *RejectedError) Error() string { return e.Message }
