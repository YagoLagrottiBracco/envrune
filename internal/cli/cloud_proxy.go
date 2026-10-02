package cli

import (
	"fmt"

	"filippo.io/age"

	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
)

// cloudProxy has what whoever runs a server needs for sensitive secrets.
func (w Workspace) cloudProxy(argv []string) int {
	if len(argv) != 1 || argv[0] != "keygen" {
		return w.usageError("cloud proxy keygen")
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return w.fail(err, "The identity could not be created.")
	}
	// The identity is a secret of the server, made to be put in its
	// configuration: it goes to standard output alone, so it can be piped.
	fmt.Fprintln(w.Stdout, identity.String())
	w.status().Warn("This is the server's proxy identity. Set it as ENVRUNE_PROXY_IDENTITY where the server runs, and nowhere else: whoever has it can read every sensitive secret sealed to it.")
	w.status().Info("Its fingerprint, which members are shown before they seal a value to it: " + cloudcrypto.ProxyFingerprint(identity.Recipient().String()))
	w.status().Info("Keep a copy somewhere safe. If it is lost, every sensitive secret has to be set again.")
	return 0
}
