build:
	go build -o vault/plugins/vault-plugin-secrets-shell cmd/vault-plugin-secrets-shell/main.go

test_plugin: build
	vault server -log-level=trace -dev -dev-root-token-id=root -dev-plugin-dir=./vault/plugins

test_commands:
	vault write sys/policies/password/example policy=@test/password-policy.hcl
	vault plugin list | grep vault-plugin-secrets-shell
	vault secrets enable -path=test vault-plugin-secrets-shell
	vault write test/config username="test" password='Testing!123' url="127.0.0.1" password_policy="example"
	vault write test/host/test.server.com host=test.server.com
	vault read test/creds/test.server.com