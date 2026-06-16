package api

import (
	"encoding/json"
	"net/http"
	"time"
)

// handleScore handles GET /api/v1/score/{ip} and returns the stored reputation
// record for that IP as JSON, including whether it is currently blocked.
func (s *Server) handleScore(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	if ip == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "missing IP"})
		return
	}

	rec, err := s.store.GetScore(ip)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	if rec.LastSeen.IsZero() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
		return
	}

	resp := struct {
		IP            string   `json:"ip"`
		Score         float64  `json:"score"`
		Corroboration int      `json:"corroboration"`
		FirstSeen     string   `json:"first_seen"`
		LastSeen      string   `json:"last_seen"`
		Reasons       []string `json:"reasons"`
		Blocked       bool     `json:"blocked"`
	}{
		IP:            ip,
		Score:         rec.Score,
		Corroboration: rec.Corroboration,
		FirstSeen:     rec.FirstSeen.UTC().Format(time.RFC3339),
		LastSeen:      rec.LastSeen.UTC().Format(time.RFC3339),
		Reasons:       rec.Reasons,
		Blocked:       rec.Score >= s.repCfg.BlockThreshold,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
