package cloud

import (
	"context"
	"fmt"
	"net/http"

	"filippo.io/age"

	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
)

// MachineValues fetches and decrypts an environment with a machine token,
// as a CI job does: no vault and no account. The token pins the
// organization's roots, so the job verifies who wrapped the key and wrote
// each value without trusting the server. The caller wipes the values.
//
// The server maps org/project/env to an environment id without a
// signature, so it could serve another environment the token may read;
// it cannot serve one outside the token's scope, or forge a value.
func MachineValues(ctx context.Context, httpClient *http.Client, server, tokenText string, path Path) (map[string][]byte, error) {
	token, err := cloudcrypto.ParseMachineToken(tokenText)
	if err != nil {
		return nil, fmt.Errorf("the machine token is malformed: %w", err)
	}
	if err := checkServer(server); err != nil {
		return nil, err
	}
	c := &Client{Server: server, HTTP: httpClient}
	payload, err := c.machineFetch(ctx, token.ID, token.Secret, path.Org, path.Project, path.Env)
	if err != nil {
		return nil, err
	}
	if payload.IDs.OrgID != token.OrgID {
		return nil, fmt.Errorf("the server answered for another organization than the token's: %w", cloudcrypto.ErrUntrusted)
	}
	ver := &verifier{orgID: token.OrgID, projectID: payload.IDs.ProjectID, envID: payload.EnvironmentID, project: path.Project, env: path.Env,
		trust: token.Trust(), certs: certificates(payload.Certificates), devices: payload.Devices}
	key, err := ver.key(payload, map[string]age.Identity{token.ID: token.Identity}, "")
	if err != nil {
		return nil, err
	}
	defer key.Wipe()
	return ver.open(payload, key, nil, true)
}
