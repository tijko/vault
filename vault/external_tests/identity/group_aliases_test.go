package identity

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/api"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/vault"

	credLdap "github.com/hashicorp/vault/builtin/credential/ldap"
)

func TestIdentityStore_GroupAliasLocalMount(t *testing.T) {
	coreConfig := &vault.CoreConfig{
		CredentialBackends: map[string]logical.Factory{
			"ldap": credLdap.Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	core := cluster.Cores[0].Core
	vault.TestWaitActive(t, core)
	client := cluster.Cores[0].Client

	// Create a local auth mount
	err := client.Sys().EnableAuthWithOptions("ldap", &api.EnableAuthOptions{
		Type:  "ldap",
		Local: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Extract out the mount accessor for LDAP auth
	auths, err := client.Sys().ListAuthWithContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ldapMountAccessor := auths["ldap/"].Accessor

	// Create an external group
	secret, err := client.Logical().WriteWithContext(context.Background(), "identity/group", map[string]interface{}{
		"type": "external",
	})
	if err != nil {
		t.Fatal(err)
	}
	groupID := secret.Data["id"].(string)

	// Attempt to create a group alias against a local mount should fail
	secret, err = client.Logical().WriteWithContext(context.Background(), "identity/group-alias", map[string]interface{}{
		"name":           "testuser",
		"mount_accessor": ldapMountAccessor,
		"canonical_id":   groupID,
	})
	if err == nil {
		t.Fatalf("expected error since mount is local")
	}
}
