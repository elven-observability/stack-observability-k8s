package main

import (
	"encoding/json"
	"net/http"
	"os"
	"runtime"
	"strings"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ready" && r.URL.Path != "/exercise" {
			http.NotFound(w, r)
			return
		}
		tid := ""
		p := strings.Split(r.Header.Get("Traceparent"), "-")
		if len(p) == 4 {
			tid = p[1]
		}
		if r.URL.Path == "/exercise" {
			json.NewEncoder(os.Stdout).Encode(map[string]any{"message": "Synthetic checkout approved", "run": "elven-saas-20261116", "trace_id": tid, "email": "synthetic-customer@example.invalid", "password": "synth-password-20261116"})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "runtime": runtime.Version(), "traceId": tid})
	})
	http.ListenAndServe(":8080", nil)
}
