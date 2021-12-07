package secrets

import (
	"context"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Factory returns a new backend as logical.Backend
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// shellBackend defines an object that
// extends the Vault backend and stores the
// target API's client.
type shellBackend struct {
	*framework.Backend
	lock   sync.RWMutex
	client *shellClient
}

// backend defines the target API backend
// for Vault. It must include each path
// and the secrets it will store.
func backend() *shellBackend {
	var b = shellBackend{}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{
				// WAL stands for Write-Ahead-Log, which is used for Vault replication
				framework.WALPrefix,
			},
			SealWrapStorage: []string{
				configStoragePath,
				hostRoleStoragePath,
			},
		},
		Paths: framework.PathAppend(
			pathConfig(&b),
			pathRole(&b),
			pathCredentials(&b),
		),
		Secrets: []*framework.Secret{
			b.credObject(),
		},
		BackendType: logical.TypeLogical,
		Invalidate:  b.invalidate,
	}
	return &b
}

// reset clears any client configuration for a new
// backend to be configured
func (b *shellBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
}

// invalidate clears an existing client configuration in
// the backend
func (b *shellBackend) invalidate(ctx context.Context, key string) {
	if key == "config" {
		b.reset()
	}
}

// getClient locks the backend as it configures and creates a
// a new client for the target API
func (b *shellBackend) getClient(ctx context.Context, s logical.Storage) (*shellClient, error) {
	b.lock.RLock()
	unlockFunc := b.lock.RUnlock
	defer func() { unlockFunc() }()

	if b.client != nil {
		return b.client, nil
	}

	b.lock.RUnlock()
	b.lock.Lock()
	unlockFunc = b.lock.Unlock

	config, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}

	if b.client == nil {
		if config == nil {
			config = new(shellConfig)
		}
	}

	b.client, err = newClient(config)
	if err != nil {
		return nil, err
	}

	return b.client, nil
}

// backendHelp should contain help information for the backend
const backendHelp = `
The secrets backend returns stored static usernames and passwords.
After mounting this backend, credentials to manage usernames and passwords
must be configured with the "config/" endpoints.
`
