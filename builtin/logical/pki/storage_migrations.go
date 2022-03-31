package pki

import (
	"context"
	"github.com/hashicorp/vault/sdk/logical"
)

func migrateStorage(ctx context.Context, req *logical.InitializationRequest) error {
	s := req.Storage
	version, err := getStorageVersion(ctx, s)
	if err != nil {
		return err
	}
	switch version {
	case 0:
		return migrateToIssuers(ctx, s)
	default:
		return nil
	}
}

func migrateToIssuers(ctx context.Context, s logical.Storage) error {
	bundle, err := getLegacyCertBundle(ctx, s)
	if err != nil {
		return err
	}
	if bundle != nil {
		err := clearPreviousUncompletedMigrations(ctx, s)
		if err != nil {
			return err
		}

		keyId, err := genKeyId()
		if err != nil {
			return err
		}
		key := &key{
			ID:             keyId,
			PrivateKeyType: bundle.PrivateKeyType,
			PrivateKey:     bundle.PrivateKey,
		}
		err = writeKey(ctx, s, key)
		if err != nil {
			return err
		}

		issuerId, err := genIssuserId()
		if err != nil {
			return err
		}
		issuer := &issuer{
			ID:           issuerId,
			Name:         "migrated",
			KeyID:        keyId,
			Certificate:  bundle.Certificate,
			CAChain:      bundle.CAChain,
			SerialNumber: bundle.SerialNumber,
		}
		err = writeIssuer(ctx, s, issuer)
		if err != nil {
			return err
		}

		err = setKeysConfig(ctx, s, &keyConfig{DefaultKeyId: keyId})
		if err != nil {
			return err
		}

		err = setIssuersConfig(ctx, s, &issuerConfig{DefaultIssuerId: issuerId})
		if err != nil {
			return err
		}
	}
	return setStorageVersion(ctx, s, 1)
}

func clearPreviousUncompletedMigrations(ctx context.Context, s logical.Storage) error {
	keys, err := listKeys(ctx, s)
	if err != nil {
		return err
	}
	for _, key := range keys {
		err := deleteKey(ctx, s, key)
		if err != nil {
			return err
		}
	}

	issuers, err := listIssuers(ctx, s)
	if err != nil {
		return err
	}
	for _, issuer := range issuers {
		err := deleteIssuer(ctx, s, issuer)
		if err != nil {
			return err
		}
	}
	return nil
}
