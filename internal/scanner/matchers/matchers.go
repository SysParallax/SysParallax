// Package matchers fournit des fonctions de détection réutilisables par tous les modules.
package matchers

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Response regroupe les éléments d'une réponse HTTP pour l'analyse.
type Response struct {
	StatusCode int
	Body       string
	Headers    http.Header
}

// Fetch exécute une requête et retourne une Response analysable.
func Fetch(client *http.Client, req *http.Request) (*Response, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	return &Response{StatusCode: resp.StatusCode, Body: string(body), Headers: resp.Header}, nil
}

var sqlErrorPatterns = []string{
	"you have an error in your sql syntax", "warning: mysql_",
	"syntax error at or near", "unterminated quoted string",
	"invalid input syntax for type", "unclosed quotation mark",
	"incorrect syntax near", "microsoft ole db provider for sql",
	"ora-01756", "ora-00933", "sqlite3.operationalerror",
	"pg_query()", "sql syntax", "database error", "db error",
}

func SQLiErrorBased(r *Response) (bool, string) {
	body := strings.ToLower(r.Body)
	for _, p := range sqlErrorPatterns {
		if strings.Contains(body, p) {
			return true, p
		}
	}
	if r.StatusCode == 500 && len(r.Body) > 50 {
		return true, "HTTP 500 (probable erreur serveur non gérée)"
	}
	return false, ""
}

func SQLiBoolean(trueResp, falseResp *Response) (bool, string) {
	if trueResp.StatusCode != falseResp.StatusCode {
		return true, fmt.Sprintf("codes HTTP différents : %d vs %d", trueResp.StatusCode, falseResp.StatusCode)
	}
	diff := len(trueResp.Body) - len(falseResp.Body)
	if diff < 0 {
		diff = -diff
	}
	if diff > 100 {
		return true, fmt.Sprintf("longueur de réponse différente : Δ%d octets", diff)
	}
	return false, ""
}

func XSSReflected(r *Response, payload string) (bool, string) {
	if r.StatusCode >= 400 || payload == "" {
		return false, ""
	}
	if strings.Contains(r.Body, payload) {
		ct := strings.ToLower(r.Headers.Get("Content-Type"))
		if strings.Contains(ct, "text/html") || ct == "" {
			return true, "payload reflété sans encodage dans une réponse HTML"
		}
	}
	return false, ""
}

var traversalPatterns = []string{
	"root:x:0:0", "daemon:x:", "/bin/bash", "/bin/sh",
	"[boot loader]", "for 16-bit app support",
	"windows/system32", "[autorun]",
}

func PathTraversal(r *Response) (bool, string) {
	body := strings.ToLower(r.Body)
	for _, p := range traversalPatterns {
		if strings.Contains(body, strings.ToLower(p)) {
			return true, fmt.Sprintf("contenu système détecté : %q", p)
		}
	}
	return false, ""
}

var ssrfPatterns = []string{
	"ami-id", "instance-id", "local-hostname", "iam/",
	"security-credentials", "169.254.169.254",
	"metadata.google.internal",
}

func SSRF(r *Response) (bool, string) {
	if r.StatusCode == 200 && len(r.Body) > 5 {
		body := strings.ToLower(r.Body)
		for _, p := range ssrfPatterns {
			if strings.Contains(body, p) {
				return true, "données metadata/réseau interne détectées"
			}
		}
	}
	return false, ""
}

func OpenRedirect(r *Response, targetURL string) (bool, string) {
	if r.StatusCode >= 300 && r.StatusCode < 400 {
		loc := r.Headers.Get("Location")
		if loc != "" && (strings.Contains(loc, targetURL) || strings.HasPrefix(loc, targetURL)) {
			return true, fmt.Sprintf("redirection vers %q", loc)
		}
	}
	return false, ""
}

func IDORAccessible(baseline, probe *Response) (bool, string) {
	if probe.StatusCode == 200 && len(probe.Body) > 30 {
		return true, fmt.Sprintf("ressource accessible sans autorisation (HTTP 200, %d octets)", len(probe.Body))
	}
	return false, ""
}
