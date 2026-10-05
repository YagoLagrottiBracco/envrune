package project

import (
	"errors"
	"net/url"
)

// ForwardTarget parses an address in forward: an https address of a
// service, with an optional path, and nothing a request would add itself.
func ForwardTarget(address string) (*url.URL, error) {
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return nil, errors.New("must be an https address, such as https://api.example.com")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("must be an address without a user, a query, or a fragment")
	}
	if port := u.Port(); port != "" && port != "443" {
		return nil, errors.New("must use the https port: sensitive secrets are only sent there")
	}
	return u, nil
}
