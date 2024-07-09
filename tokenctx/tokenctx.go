package tokenctx

import (
	"context"
	"fmt"

	"github.com/RMI/credential-service/allowlist"
)

type emailsContextKey struct{}

func AddEmailsToContext(ctx context.Context, emails []string) context.Context {
	return context.WithValue(ctx, emailsContextKey{}, emails)
}

func EmailsFromContext(ctx context.Context) ([]string, error) {
	v := ctx.Value(emailsContextKey{})
	if v == nil {
		return nil, fmt.Errorf("no email found in context")
	}
	emails, ok := v.([]string)
	if !ok {
		return nil, fmt.Errorf("wrong type for email in context: %T", v)
	}
	return emails, nil
}

type allowlistContextKey struct{}

func AddAllowlistEntityToContext(ctx context.Context, ae *allowlist.Entity) context.Context {
	return context.WithValue(ctx, allowlistContextKey{}, ae)
}

func AllowlistEntityFromContext(ctx context.Context) (*allowlist.Entity, error) {
	v := ctx.Value(allowlistContextKey{})
	if v == nil {
		return nil, fmt.Errorf("no allowlist entity found in context")
	}
	entity, ok := v.(*allowlist.Entity)
	if !ok {
		return nil, fmt.Errorf("wrong type for allowlist entity in context: %T", v)
	}
	return entity, nil
}
