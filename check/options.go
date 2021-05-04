package check

import "context"

type Options struct {
	ctx           context.Context
	collectTiming bool
	nameserver    string
}

type Option func(*Options)

// WithContext sets the context used with a check execution.
func WithContext(ctx context.Context) Option {
	return func(options *Options) {
		options.ctx = ctx
	}
}

// CollectTiming directs the check execution to collecting timing facts.
func CollectTiming() Option {
	return func(options *Options) {
		options.collectTiming = true
	}
}

// UseNameserver directs the check execution to use a specific nameserver to
// resolve the target/host.
func UseNameserver(nameserver string) Option {
	return func(options *Options) {
		options.nameserver = nameserver
	}
}
