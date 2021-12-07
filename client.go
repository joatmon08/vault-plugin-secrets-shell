package secrets

import (
	"errors"
)

// shellClient creates an object storing
// the client.
type shellClient struct {
	// add your client here
}

// newClient creates a new client to access your endpoint
// and exposes it for any secrets or roles to use.
// TODO: Implement code to call your client.
func newClient(config *shellConfig) (*shellClient, error) {
	if config == nil {
		return nil, errors.New("client configuration was nil")
	}

	if config.Username == "" {
		return nil, errors.New("client username was not defined")
	}

	if config.Password == "" {
		return nil, errors.New("client password was not defined")
	}

	if config.URL == "" {
		return nil, errors.New("client URL was not defined")
	}

	return &shellClient{}, nil
}
