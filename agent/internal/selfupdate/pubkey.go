package selfupdate

// SigningPublicKeyPEM is the cosign public key (cosign.pub, PKIX/SPKI PEM)
// that signs the release artifacts. Generate it once, out of band:
//
//	cosign generate-key-pair            # -> cosign.key (encrypted), cosign.pub
//
// then:
//   - paste cosign.pub's contents between the backticks below,
//   - copy the same file to deploy/cosign.pub (used by install.sh),
//   - add the GitHub Actions secrets COSIGN_KEY (cosign.key contents) and
//     COSIGN_PASSWORD.
//
// While this is empty, self-update is DISABLED: an unverifiable binary is
// never swapped in (see selfupdate.Apply).
var SigningPublicKeyPEM = []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEovecmqAlb8lTaWlZZm96EVMpEN6U
e5hNrJHNFxbmjJzWZR5Gih5FNBM/xgw2B0nPc9WoSqrs5PKzleHtfA4vgQ==
-----END PUBLIC KEY-----
`)
