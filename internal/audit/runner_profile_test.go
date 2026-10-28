package audit

import (
	"testing"

	"github.com/auditcore/auditcore/internal/models"
	"github.com/auditcore/auditcore/internal/scanner/engine"
	"github.com/auditcore/auditcore/internal/storage"
)

func TestPhaseEnabledUsesProfilePhases(t *testing.T) {
	options := models.AuditOptions{
		EnabledPhases: []models.Phase{models.PhasePreCheck, models.PhasePassive, models.PhaseReport},
	}

	if !phaseEnabled(options, models.PhasePassive) {
		t.Fatal("expected passive phase to be enabled")
	}
	if phaseEnabled(options, models.PhaseActive) {
		t.Fatal("expected active phase to be disabled")
	}
}

func TestRegisterActiveModulesUsesAllowlistAliases(t *testing.T) {
	e := engine.New(storage.New(), models.AuditOptions{})
	count := registerActiveModules(e, models.AuditOptions{ActiveModules: []string{"sqli", "xss"}})

	if count != 2 {
		t.Fatalf("expected two active modules, got %d", count)
	}
}

func TestRegisterActiveModulesCanDisableAllModules(t *testing.T) {
	e := engine.New(storage.New(), models.AuditOptions{})
	count := registerActiveModules(e, models.AuditOptions{ActiveModules: []string{}})

	if count != 0 {
		t.Fatalf("expected active modules to be disabled, got %d", count)
	}
}
