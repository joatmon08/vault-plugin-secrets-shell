package secrets

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	credObjectType = "cred_object"
)

// credObject defines a username and password
type credObject struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (b *shellBackend) credObject() *framework.Secret {
	return &framework.Secret{
		Type: credObjectType,
		Fields: map[string]*framework.FieldSchema{
			"username": {
				Type:        framework.TypeString,
				Description: "My Credentials Object username",
			},
			"password": {
				Type:        framework.TypeString,
				Description: "My Credentials Object password",
			},
		},
		Revoke: b.revoke,
		Renew:  b.renew,
	}
}

// revoke removes the credentials object from the Vault storage API and calls the client to revoke the token
func (b *shellBackend) revoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("error getting client: %w", err)
	}

	username := ""
	// We passed the username using InternalData from when we first created
	// the secret.
	usernameRaw, ok := req.Secret.InternalData["username"]
	if ok {
		username, ok = usernameRaw.(string)
		if !ok {
			return nil, fmt.Errorf("invalid value for username in secret internal data")
		}
	}

	if err := revokeCredentials(ctx, client, username); err != nil {
		return nil, fmt.Errorf("error revoking username: %w", err)
	}
	return nil, nil
}

// renew calls the client to create a new password and stores it in the Vault storage API
func (b *shellBackend) renew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleRaw, ok := req.Secret.InternalData["role"]
	if !ok {
		return nil, fmt.Errorf("secret is missing role internal data")
	}

	// get the role entry
	role := roleRaw.(string)
	roleEntry, err := b.getRole(ctx, req.Storage, role)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	if roleEntry == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	resp := &logical.Response{Secret: req.Secret}

	if roleEntry.TTL > 0 {
		resp.Secret.TTL = roleEntry.TTL
	}
	if roleEntry.MaxTTL > 0 {
		resp.Secret.MaxTTL = roleEntry.MaxTTL
	}

	return resp, nil
}

// TODO: Implement code to retrieve username and password
// You can reference https://github.com/hashicorp/vault-plugin-secrets-openldap/blob/main/rotation.go
// for an example of how to rotate usernames and passwords using rotation periods.
func getCredentials(ctx context.Context, c *shellClient) (*credObject, error) {
	return &credObject{
		Username: "foo",
	}, nil
}

// TODO: Implement code to revoke username and password
func revokeCredentials(ctx context.Context, c *shellClient, username string) error {
	return nil
}
