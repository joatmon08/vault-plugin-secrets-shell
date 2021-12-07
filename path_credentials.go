package secrets

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	credsStoragePath = "creds/"
	credsPath        = "creds/"
)

// pathCredentials extends the Vault API with a `/creds`
// endpoint for a role. You can choose whether
// or not certain attributes should be displayed,
// required, and named.
func pathCredentials(b *shellBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: credsPath + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the role",
					Required:    true,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.pathCredentialsRead,
				logical.UpdateOperation: b.pathCredentialsRead,
			},

			HelpSynopsis:    pathCredentialsHelpSyn,
			HelpDescription: pathCredentialsHelpDesc,
		},
	}
}

// pathCredentialsRead gets the password each time it is called if a
// role exists.
func (b *shellBackend) pathCredentialsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("name").(string)

	roleEntry, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	if roleEntry == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	return b.create(ctx, req, roleEntry)
}

// create to store into the Vault backend, generates
// a response with the secrets information, and checks the TTL and MaxTTL attributes.
func (b *shellBackend) create(ctx context.Context, req *logical.Request, role *shellRoleEntry) (*logical.Response, error) {
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	// TODO: You can add log messages using the logger object in backend.
	b.Logger().Debug("getting username and password for host")

	creds, err := getCredentials(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("error getting credentials: %w", err)
	}
	// The response is divided into two objects (1) internal data and (2) data.
	// If you want to reference any information in your code, you need to
	// store it in internal data!
	resp := b.Secret(credObjectType).Response(map[string]interface{}{
		"username": creds.Username,
		"password": creds.Password,
	}, map[string]interface{}{
		"role": role.Name,
	})

	if role.TTL > 0 {
		resp.Secret.TTL = role.TTL
	}

	if role.MaxTTL > 0 {
		resp.Secret.MaxTTL = role.MaxTTL
	}
	return resp, nil
}

const pathCredentialsHelpSyn = `
Generate a credentials object from a specific Vault role.
`

const pathCredentialsHelpDesc = `
This path generates a credentials object
based on a particular role.
`
