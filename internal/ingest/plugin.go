// Package ingest turns external attack signals into proto.Event reports.
//
// A Source is a plugin that observes some system (mail logs, a honeypot, a
// CrowdSec instance, ...) and emits Events. New integrations are added by
// implementing Source and registering it — see .claude/skills/add-ingest-plugin
// and docs/plugins.md.
package ingest

import (
	"context"

	"github.com/JoeRu/swarmguard/pkg/proto"
)

// Source is the plugin contract for an attack-signal producer.
type Source interface {
	// Name is the stable identifier of the source (e.g. "crowdsec", "cowrie").
	Name() string
	// Start begins emitting Events on the returned channel until ctx is cancelled.
	Start(ctx context.Context) (<-chan proto.Event, error)
}

// registry holds the available sources by name.
var registry = map[string]func() Source{}

// Register makes a Source available under its name. Called from adapter init().
func Register(name string, factory func() Source) { registry[name] = factory }

// Available lists registered source names.
func Available() []string {
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	return out
}
