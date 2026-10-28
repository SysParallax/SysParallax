package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

func NewRouter(h *Handler, dashboardDir string) http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Accept", "Content-Type", "Authorization"},
	}))

	r.Route("/api", func(r chi.Router) {
		r.Get("/health", h.Health)
		r.Get("/stats", h.GetStats)
		r.Get("/trends", h.GetTrends)

		r.Route("/audits", func(r chi.Router) {
			r.Post("/", h.CreateAudit)
			r.Get("/", h.ListAudits)

			r.Route("/{id}", func(r chi.Router) {
				r.Get("/", h.GetAudit)
				r.Get("/events", h.GetEvents)
				r.Get("/precheck", h.GetPreCheck)
				r.Get("/network", h.GetNetwork)
				r.Get("/recon", h.GetRecon)
				r.Get("/fingerprint", h.GetFingerprint)
				r.Get("/crawl", h.GetCrawl)
				r.Get("/report", h.GetReport)
				r.Get("/active-tests", h.GetActiveTests)
				r.Get("/active-stats", h.GetActiveStats)
				r.Get("/active-summary", h.GetActiveSummary)
				r.Post("/stop", h.StopAudit)
				r.Get("/assets", h.GetAssets)
				r.Get("/findings", h.GetFindings)

				r.Route("/findings/{fid}", func(r chi.Router) {
					r.Patch("/", h.PatchFinding)
					r.Post("/replay", h.ReplayFinding)
				})
			})
		})
	})

	// Dashboard statique
	if dashboardDir != "" {
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, dashboardDir+"/index.html")
		})
		r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.Dir(dashboardDir))))
		r.Get("/*", serveDashboardRoute(dashboardDir))
	}

	return r
}

// serveDashboardRoute sert les assets existants et renvoie index.html pour les
// routes applicatives. Les chemins API et les assets manquants restent en 404.
func serveDashboardRoute(dashboardDir string) http.HandlerFunc {
	baseDir, err := filepath.Abs(dashboardDir)
	if err != nil {
		baseDir = dashboardDir
	}
	return func(w http.ResponseWriter, r *http.Request) {
		requested := strings.TrimPrefix(chi.URLParam(r, "*"), "/")
		if requested == "api" || strings.HasPrefix(requested, "api/") {
			http.NotFound(w, r)
			return
		}

		cleanPath := filepath.Clean(filepath.FromSlash(requested))
		fullPath := filepath.Join(baseDir, cleanPath)
		relativePath, relErr := filepath.Rel(baseDir, fullPath)
		insideDashboard := relErr == nil && relativePath != ".." && !strings.HasPrefix(relativePath, ".."+string(filepath.Separator))
		if requested != "" && insideDashboard {
			if info, statErr := os.Stat(fullPath); statErr == nil && !info.IsDir() {
				http.ServeFile(w, r, fullPath)
				return
			}
		}

		if filepath.Ext(cleanPath) != "" {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(baseDir, "index.html"))
	}
}
