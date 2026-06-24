package trust

import (
	"github.com/JoeRu/federloom/pkg/proto"
)

// Bundle is the offline exchange format produced by `federloomctl trust export`
// and consumed by `federloomctl trust import`: a Person's public identity plus
// every peer-cert they have issued. The importer chooses the local Person
// name; Label is the exporter's suggestion.
type Bundle struct {
	Person         string           `json:"person"`
	Label          string           `json:"label"`
	IdentityPubkey string           `json:"identity_pubkey"`
	Certs          []proto.PeerCert `json:"certs"`
}
