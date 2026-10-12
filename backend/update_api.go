package main

import (
	"context"
	"net/http"
	"strings"
	"time"
)

func (a *API) serializeUpdateMutations(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if strings.HasPrefix(r.URL.Path, "/api/updates/") {
				a.mutationMu.Lock()
				defer a.mutationMu.Unlock()
			} else {
				a.mutationMu.RLock()
				defer a.mutationMu.RUnlock()
			}
		}
		if r.Context().Err() != nil {
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) updateMihomo(w http.ResponseWriter, r *http.Request) {
	a.subOp.Lock()
	defer a.subOp.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), mihomoPrepareTimeout+50*time.Second)
	defer cancel()
	result, err := a.manager.UpdateMihomo(ctx, callPrivilegedHelper)
	if err != nil {
		a.recordEvent("mihomo_update_failed")
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error(), "result": result})
		return
	}
	a.recordEvent("mihomo_updated")
	writeJSON(w, http.StatusOK, result)
}
