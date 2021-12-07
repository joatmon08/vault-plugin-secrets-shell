build:
	go build -o vault/plugins/vault-plugin-secrets-shell cmd/vault-plugin-secrets-shell/main.go

test_plugin: build
	vault server -log-level=trace -dev -dev-root-token-id=root -dev-plugin-dir=./vault/plugins

test_commands:
	vault plugin list | grep vault-plugin-secrets-shell
	vault secrets enable -path=idrac vault-plugin-secrets-shell
	vault write idrac/config username="idrac" password='Testing!123' url="127.0.0.1"
	vault write idrac/host/bmc.server.com host=bmc.server.com
	vault read idrac/creds/bmc.server.com