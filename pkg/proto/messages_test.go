package proto_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/JoeRu/federloom/pkg/proto"
)

func TestEventVouchRoundTrip(t *testing.T) {
	e := proto.Event{
		IP:         "192.0.2.1",
		Reason:     "ssh-auth-bruteforce",
		Timestamp:  time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC),
		ReporterID: "12D3KooWtest",
		Vouch: &proto.PeerCert{
			PeerID:     "12D3KooWtest",
			PersonKey:  []byte{1, 2, 3, 4},
			ValidUntil: time.Date(2027, 6, 12, 12, 0, 0, 0, time.UTC),
			Sig:        []byte{9, 8, 7},
		},
	}
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got proto.Event
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Vouch == nil {
		t.Fatal("Vouch lost in round trip")
	}
	if got.Vouch.PeerID != e.Vouch.PeerID || !got.Vouch.ValidUntil.Equal(e.Vouch.ValidUntil) {
		t.Errorf("Vouch mismatch: got %+v want %+v", got.Vouch, e.Vouch)
	}
	// PersonKey and Sig are the security-critical bytes — verify they survive intact.
	if !bytes.Equal(got.Vouch.PersonKey, e.Vouch.PersonKey) {
		t.Errorf("PersonKey mismatch: got %v want %v", got.Vouch.PersonKey, e.Vouch.PersonKey)
	}
	if !bytes.Equal(got.Vouch.Sig, e.Vouch.Sig) {
		t.Errorf("Sig mismatch: got %v want %v", got.Vouch.Sig, e.Vouch.Sig)
	}
}

// TestEventLegacyDecode proves a v0 event (no vouch field) decodes with Vouch nil
// — the additive-compatibility guarantee of the SchemaVersion 0→1 bump.
func TestEventLegacyDecode(t *testing.T) {
	legacy := []byte(`{"ip":"192.0.2.1","reason":"spam","ts":"2026-06-12T12:00:00Z","port_class":"","reporter":"x","sig":null,"subnet":"","origin":null}`)
	var got proto.Event
	if err := json.Unmarshal(legacy, &got); err != nil {
		t.Fatalf("unmarshal legacy: %v", err)
	}
	if got.Vouch != nil {
		t.Errorf("legacy event must have nil Vouch, got %+v", got.Vouch)
	}
}

// TestEventWithoutVouchOmitsField proves omitempty: stranger events carry no vouch key.
func TestEventWithoutVouchOmitsField(t *testing.T) {
	data, err := json.Marshal(proto.Event{IP: "192.0.2.1"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	if _, ok := m["vouch"]; ok {
		t.Error("vouch key present on event without vouch — omitempty missing")
	}
}

func TestSchemaVersionBumped(t *testing.T) {
	if proto.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1 (vouching added)", proto.SchemaVersion)
	}
}
