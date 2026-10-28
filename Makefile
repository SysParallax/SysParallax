.PHONY: run build test clean tidy check

# Lance le serveur avec le dashboard
run:
	go run ./cmd/api/

# Lance sur un port personnalisé
run-port:
	go run ./cmd/api/ -port=$(PORT)

# Compile le binaire
build:
	go build -o bin/auditcore ./cmd/api/

# Télécharge les dépendances
tidy:
	go mod tidy

# Vérifie que tout compile sans erreurs
check:
	go build ./...

# Tests unitaires (à implémenter)
test:
	go test ./...

# Nettoie les binaires
clean:
	rm -rf bin/

# Exemple de lancement d'audit via curl
audit-example:
	curl -s -X POST http://localhost:8080/api/audits \
		-H "Content-Type: application/json" \
		-d '{"target_url":"https://example.com"}' | python3 -m json.tool

# Santé de l'API
health:
	curl -s http://localhost:8080/api/health | python3 -m json.tool
