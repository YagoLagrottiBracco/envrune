package cli

import (
	"fmt"
	"strings"
	"sync"

	"github.com/YagoLagrottiBracco/envrune/internal/app"
	"github.com/YagoLagrottiBracco/envrune/internal/cloud"
	"github.com/YagoLagrottiBracco/envrune/internal/project"
	"github.com/YagoLagrottiBracco/envrune/internal/runner"
	"github.com/YagoLagrottiBracco/envrune/internal/sealproxy"
)

// seal prepares the sensitive cloud secrets a command is about to use. Such
// a secret never reaches this machine: the command gets a placeholder, and
// its requests to the hosts the secret allows go through a proxy on this
// computer to the server, which puts the value in (docs/managed-keys.md).
//
// It returns the variables that point the command at the proxy and a
// function to call when the command has ended. With no sensitive secret in
// the environment it does nothing. It needs the server: a sensitive secret
// cannot be used offline.
func (w Workspace) seal(projectPath, environment string) ([]runner.Pair, func(), error) {
	none := func() {}
	config, err := project.Load(projectPath)
	if err != nil || config.Cloud == "" || w.Session == nil {
		return nil, none, nil
	}
	chosen, err := app.ChooseEnvironment(config, environment)
	if err != nil {
		return nil, none, nil
	}
	var named []cloud.Path
	for _, ref := range config.Environments[chosen] {
		if path, isCloud, err := cloud.ReferencePath(ref.String(), config.Cloud, chosen); isCloud && err == nil {
			named = append(named, path)
		}
	}
	service := w.cloudService()
	sensitive, err := service.SensitiveNames(named)
	if err != nil || len(sensitive) == 0 {
		return nil, none, nil
	}
	ctx, cancel := cloudContext()
	defer cancel()
	forwarder, err := service.Forwarder(ctx, sensitive)
	if err != nil {
		return nil, none, fmt.Errorf("%s is a sensitive secret, which needs the server: %w", sensitive[0], err)
	}
	proxy, err := sealproxy.Start(forwarder)
	if err != nil {
		return nil, none, err
	}
	// The same refusal, such as being offline, is said once, not per request.
	var mu sync.Mutex
	told := map[string]bool{}
	proxy.Refused = func(host string, err error) {
		mu.Lock()
		defer mu.Unlock()
		if !told[host+err.Error()] {
			told[host+err.Error()] = true
			w.status().Warn(fmt.Sprintf("A request to %s was not forwarded: %s.", host, strings.TrimRight(err.Error(), ".")))
		}
	}
	variables, err := proxy.Environment(w.environ())
	if err != nil {
		proxy.Close()
		return nil, none, err
	}
	placeholders := map[string][]byte{}
	var names, hosts []string
	for _, s := range forwarder.Sealed() {
		placeholders[s.Path.String()] = []byte(s.Placeholder)
		names = append(names, s.Path.Name)
		hosts = append(hosts, s.Hosts...)
	}
	unseal := w.Session.Seal(placeholders)
	pairs := make([]runner.Pair, 0, len(variables))
	for _, v := range variables {
		pairs = append(pairs, runner.Pair{Name: v[0], Value: []byte(v[1])})
	}
	w.status().Info(fmt.Sprintf("%s never %s this computer: requests to %s go through the server, which adds %s.",
		strings.Join(names, ", "), plural(len(names), "reaches", "reach"), strings.Join(hosts, ", "), plural(len(names), "it", "them")))
	return pairs, func() {
		proxy.Close()
		unseal()
	}, nil
}
