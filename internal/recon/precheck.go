// Package recon contient les phases de reconnaissance passive.
package recon

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/auditcore/auditcore/internal/httpx"
	"github.com/auditcore/auditcore/internal/models"
	"github.com/auditcore/auditcore/internal/storage"
)

// PreChecker exécute la phase pre-check.
type PreChecker struct {
	store  *storage.Store
	client *http.Client
}

// NewPreChecker crée un PreChecker avec un client HTTP configuré.
func NewPreChecker(store *storage.Store, options models.AuditOptions) *PreChecker {
	return &PreChecker{
		store:  store,
		client: httpx.NewClient(15*time.Second, options),
	}
}

// Run exécute le pre-check sur targetURL et sauvegarde le résultat.
func (pc *PreChecker) Run(auditRunID, targetURL string) (*models.PreCheckResult, error) {
	result := &models.PreCheckResult{
		AuditRunID: auditRunID,
		CheckedAt:  time.Now(),
	}

	// 1. Valider et normaliser l'URL
	normalized, err := normalizeURL(targetURL)
	if err != nil {
		result.Error = err.Error()
		pc.store.SavePreCheck(result)
		return result, fmt.Errorf("URL invalide : %w", err)
	}
	result.FinalURL = normalized

	// 2. Requête HTTP HEAD d'abord, fallback GET
	start := time.Now()
	resp, err := pc.client.Head(normalized)
	if err != nil {
		// HEAD échoue sur certains serveurs — on tente GET
		resp, err = pc.client.Get(normalized)
		if err != nil {
			result.Reachable = false
			result.Error = err.Error()
			pc.store.SavePreCheck(result)
			return result, nil // Pas fatal pour l'appelant — on retourne sans erreur Go
		}
	}
	defer resp.Body.Close()

	elapsed := time.Since(start)

	// 3. Enregistrer l'URL finale après redirections
	if resp.Request != nil && resp.Request.URL != nil {
		result.FinalURL = resp.Request.URL.String()
	}

	result.StatusCode = resp.StatusCode
	result.ResponseTime = elapsed
	result.Reachable = resp.StatusCode < 500

	pc.store.SavePreCheck(result)
	return result, nil
}

// normalizeURL valide et normalise une URL.
// Ajoute "https://" si aucun schéma n'est présent.
func normalizeURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("URL vide")
	}

	// Ajouter le schéma si absent
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "https://" + raw
	}

	u, err := url.ParseRequestURI(raw)
	if err != nil {
		return "", fmt.Errorf("URL mal formée : %w", err)
	}

	if u.Host == "" {
		return "", fmt.Errorf("hôte manquant dans l'URL")
	}

	// Supprimer le fragment (#...) qui n'a pas de sens pour un scan
	u.Fragment = ""
	return u.String(), nil
}
