package secrets

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configStoragePath = "config"
	configPath        = "config"
)

type shellConfig struct {
	Username       string `json:"username"`
	Password       string `json:"password"`
	URL            string `json:"url"`
	PasswordPolicy string `json:"password_policy,omitempty"`
}

func pathConfig(b *shellBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: configPath,
			Fields:  b.configFields(),
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathConfigWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathConfigWrite,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathConfigRead,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathConfigDelete,
				},
			},
			ExistenceCheck:  b.pathConfigExistenceCheck,
			HelpSynopsis:    "Some secrets engine configuration",
			HelpDescription: "This path configures some secrets engine using a username, password, and URL.",
		},
	}
}

func (b *shellBackend) configFields() map[string]*framework.FieldSchema {
	return map[string]*framework.FieldSchema{
		"username": {
			Type:        framework.TypeString,
			Description: "The username to access target API",
			Required:    true,
			DisplayAttrs: &framework.DisplayAttributes{
				Name:      "Username",
				Sensitive: false,
			},
		},
		"password": {
			Type:        framework.TypeString,
			Description: "The user's password to access target API",
			Required:    true,
			DisplayAttrs: &framework.DisplayAttributes{
				Name:      "Password",
				Sensitive: true,
			},
		},
		"url": {
			Type:        framework.TypeString,
			Description: "The URL for the target API",
			Required:    true,
			DisplayAttrs: &framework.DisplayAttributes{
				Name:      "URL",
				Sensitive: false,
			},
		},
		"password_policy": {
			Type:        framework.TypeString,
			Description: "Password policy to use to generate passwords",
			Required:    false,
		},
		"ttl": {
			Type:        framework.TypeDurationSecond,
			Description: "The default password time-to-live.",
		},
		"max_ttl": {
			Type:        framework.TypeDurationSecond,
			Description: "The maximum password time-to-live.",
		},
	}
}

// pathConfigExistenceCheck verifies if the configuration exists.
func (b *shellBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}

	return out != nil, nil
}

// pathConfigRead reads the configuration and outputs non-sensitive information.
func (b *shellBackend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	// "password" is intentionally not returned by this endpoint
	return &logical.Response{
		Data: map[string]interface{}{
			"username":        config.Username,
			"url":             config.URL,
			"password_policy": config.PasswordPolicy,
		},
	}, nil
}

// pathConfigWrite updates the configuration for the backend
func (b *shellBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if config == nil {
		if req.Operation == logical.UpdateOperation {
			return nil, errors.New("config not found during update operation")
		}
		config = new(shellConfig)
	}

	username := data.Get("username").(string)
	url := data.Get("url").(string)
	passwordPolicy := data.Get("password_policy").(string)

	config.Username = username
	config.URL = url
	config.PasswordPolicy = passwordPolicy

	password, ok := data.GetOk("password")
	if ok {
		config.Password = password.(string)
	}

	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	// reset the client so the next invocation will pick up the new configuration
	b.reset()

	return nil, nil
}

// pathConfigDelete removes the configuration for the backend
func (b *shellBackend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, configStoragePath)

	if err == nil {
		b.reset()
	}

	return nil, err
}

func getConfig(ctx context.Context, s logical.Storage) (*shellConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	config := new(shellConfig)
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, fmt.Errorf("error reading root configuration: %w", err)
	}

	// return the config, we are done
	return config, nil
}
