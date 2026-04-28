package mcp

type upstreamApplicationError struct {
	code    int
	message string
}

func newUpstreamApplicationError(rpcErr *rpcError) error {
	if rpcErr == nil {
		return nil
	}
	return &upstreamApplicationError{
		code:    rpcErr.Code,
		message: rpcErr.Message,
	}
}

func (e *upstreamApplicationError) Error() string {
	if e == nil {
		return ""
	}
	return e.message
}
