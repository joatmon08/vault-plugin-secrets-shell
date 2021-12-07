# vault-plugin-secrets-shell

## Build

To build, run `make build`.

## Run

To test the plugin end-to-end, run:

```shell
make test_plugin
```

This builds the plugin and starts a Vault dev server with
traces enabled.

Then, run commands to configure the secrets engine via:

```shell
make test_commands
```

## Editing

If you want to edit the shell of this code, you can look for the TODO comments.

```
// TODO:
```

They will highlight some of the functions you can edit.

## Additional References

- [Tutorial Collection](https://learn.hashicorp.com/collections/vault/custom-secrets-engine)
- [Example with OpenLDAP Secrets Engine](https://github.com/hashicorp/vault-plugin-secrets-openldap/blob/main/rotation.go)