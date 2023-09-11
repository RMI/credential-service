package emailctx

import (
	"context"
	"fmt"
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
