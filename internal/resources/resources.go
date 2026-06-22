package resources

import _ "embed"

// RelayList is the bundled bootstrap relay list (spec §14.2).
// Operators can override it via config discovery.relay_list_path.
//
//go:embed relay-list.json
var RelayList []byte
