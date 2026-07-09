package repquery

import (
	"testing"
	"time"

	"github.com/JoeRu/federloom/internal/store"
)

func TestEntryRecordRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	rec := store.ScoreRecord{
		Score:         42.5,
		Corroboration: 3,
		FirstSeen:     now.Add(-time.Hour),
		LastSeen:      now,
		Reasons:       []string{"ssh-probe", "smtp-auth-bruteforce"},
	}
	e := EntryFromRecord("1.2.3.4", rec)
	if e.IP != "1.2.3.4" || e.Score != 42.5 || e.Corroboration != 3 {
		t.Fatalf("EntryFromRecord lost fields: %+v", e)
	}
	back := RecordFromEntry(e)
	if back.Score != rec.Score || back.Corroboration != rec.Corroboration ||
		!back.LastSeen.Equal(rec.LastSeen) || !back.FirstSeen.Equal(rec.FirstSeen) ||
		len(back.Reasons) != len(rec.Reasons) {
		t.Errorf("round trip lost fields: got %+v want %+v", back, rec)
	}
}
