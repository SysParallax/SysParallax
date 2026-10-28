// cmd/api/main.go — AuditCore V2
// Lance le serveur API + sert le dashboard statique depuis web/dashboard/
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/auditcore/auditcore/internal/api"
	"github.com/auditcore/auditcore/internal/audit"
	"github.com/auditcore/auditcore/internal/storage"
)

func main() {
	port := flag.String("port", envOr("PORT", "8080"), "port d'écoute")
	dashDir := flag.String("dash", "", "répertoire du dashboard (auto-détecté si vide)")
	flag.Parse()

	// Auto-détection du répertoire dashboard
	if *dashDir == "" {
		// Chercher web/dashboard depuis le répertoire courant
		candidates := []string{
			"web/dashboard",
			"../web/dashboard",
			"../../web/dashboard",
		}
		for _, c := range candidates {
			abs, _ := filepath.Abs(c)
			if _, err := os.Stat(abs + "/index.html"); err == nil {
				*dashDir = abs
				break
			}
		}
	}

	if *dashDir == "" {
		log.Println("[warn] Dashboard non trouvé — serveur API uniquement")
		log.Println("[warn] Placer index.html dans web/dashboard/ ou utiliser -dash=<chemin>")
	} else {
		log.Printf("[info] Dashboard : %s", *dashDir)
	}

	// Dépendances
	store := storage.New()
	runner := audit.New(store)
	handler := api.New(store, runner)
	router := api.NewRouter(handler, *dashDir)

	addr := fmt.Sprintf(":%s", *port)

	log.Println("╔══════════════════════════════════════════════╗")
	log.Printf("║  AuditCore V2  —  http://localhost%s        ║", addr)
	log.Println("╚══════════════════════════════════════════════╝")
	if *dashDir != "" {
		log.Printf("  Dashboard  : http://localhost%s/", addr)
	}
	log.Printf("  Health     : http://localhost%s/api/health", addr)
	log.Printf("  Stats      : http://localhost%s/api/stats", addr)
	log.Printf("  Audits     : http://localhost%s/api/audits", addr)
	log.Println("")
	log.Println("  Exemple lancement rapide :")
	log.Printf(`  curl -X POST http://localhost%s/api/audits -H "Content-Type: application/json" -d '{"target_url":"https://example.com"}'`, addr)
	log.Println("")

	if err := http.ListenAndServe(addr, router); err != nil {
		log.Fatalf("[fatal] server: %v", err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
