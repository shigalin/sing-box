package snell

import "context"

type requestAcceptedKey struct{}

// ContextWithRequestAccepted registers a function that a single-PSK v5 or v6
// Service calls once, synchronously, when it has decrypted and validated the
// first request of the connection served with the returned context, before
// that request is handled. A caller that selected the service from an
// authenticated header prefix can keep its handshake limits until then.
func ContextWithRequestAccepted(ctx context.Context, accepted func()) context.Context {
	return context.WithValue(ctx, requestAcceptedKey{}, accepted)
}

// RequestAccepted runs the function registered with ContextWithRequestAccepted.
func RequestAccepted(ctx context.Context) {
	if accepted, _ := ctx.Value(requestAcceptedKey{}).(func()); accepted != nil {
		accepted()
	}
}
