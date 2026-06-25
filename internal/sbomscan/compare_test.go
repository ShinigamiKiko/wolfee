package sbomscan

import (
	"testing"

	"sca-go/cli/internal/onlinescan"
)

func comp(purl, name, ver, scope string, vulns ...onlinescan.Vulnerability) ComponentReport {
	c := ComponentReport{PURL: purl, System: "golang", Name: name, Version: ver, Scope: scope, Vulnerabilities: vulns, Origin: OriginApp}
	c.TopSeverity, c.VulnCount = topAndCount(vulns)
	return c
}

func TestMergeSourceVulns(t *testing.T) {
	image := &Report{Components: []ComponentReport{
		comp("pkg:golang/github.com/jackc/pgx/v5@v5.7.2", "github.com/jackc/pgx/v5", "v5.7.2", "",
			onlinescan.Vulnerability{ID: "CVE-1111", CVE: "CVE-1111", Severity: "HIGH"}),
		{PURL: "pkg:apk/alpine/musl@1.2", System: "apk", Name: "musl", Version: "1.2", Origin: OriginImage,
			Vulnerabilities: []onlinescan.Vulnerability{{ID: "CVE-9999", CVE: "CVE-9999", Severity: "HIGH"}}},
	}}
	source := &Report{Components: []ComponentReport{

		comp("pkg:golang/github.com/jackc/pgx/v5@v5.7.2", "github.com/jackc/pgx/v5", "v5.7.2", "optional",
			onlinescan.Vulnerability{ID: "CVE-2222", CVE: "CVE-2222", Severity: "HIGH"}),

		comp("pkg:golang/golang.org/x/text@v0.3.0", "golang.org/x/text", "v0.3.0", "required",
			onlinescan.Vulnerability{ID: "CVE-3333", CVE: "CVE-3333", Severity: "MEDIUM"}),

		comp("pkg:golang/example.com/clean@v1.0.0", "example.com/clean", "v1.0.0", "required"),
	}}

	MergeSourceVulns(image, source, nil)

	byName := map[string]ComponentReport{}
	for _, c := range image.Components {
		byName[c.Name] = c
	}
	pgx := byName["github.com/jackc/pgx/v5"]
	if pgx.VulnCount != 2 {
		t.Errorf("pgx vulns after union = %d, want 2 (CVE-1111 + CVE-2222)", pgx.VulnCount)
	}
	if pgx.Scope != "optional" {
		t.Errorf("pgx scope = %q, want optional (transitive, from source)", pgx.Scope)
	}
	if _, ok := byName["golang.org/x/text"]; !ok {
		t.Error("source-only vulnerable lib golang.org/x/text was not added")
	}
	if _, ok := byName["example.com/clean"]; ok {
		t.Error("source-only CLEAN lib example.com/clean must not be added")
	}

	if image.Totals.Transitive != 1 {
		t.Errorf("Transitive = %d, want 1 (pgx)", image.Totals.Transitive)
	}
	if image.Totals.Direct != 1 {
		t.Errorf("Direct = %d, want 1 (x/text)", image.Totals.Direct)
	}
}

func TestSourceScopeMap_GoIndirectProperty(t *testing.T) {
	bom := []byte(`{"components":[
		{"purl":"pkg:golang/example.com/direct@v1.0.0"},
		{"purl":"pkg:golang/example.com/indirect@v1.0.0","properties":[{"name":"cdx:go:indirect","value":"true"}]},
		{"purl":"pkg:npm/left-pad@1.3.0","scope":"optional"}
	]}`)
	m := SourceScopeMap(bom)
	if m["pkg:golang/example.com/indirect"] != "optional" {
		t.Errorf("go indirect not mapped to optional: %v", m)
	}
	if m["pkg:npm/left-pad"] != "optional" {
		t.Errorf("npm scope not preserved: %v", m)
	}
	if _, ok := m["pkg:golang/example.com/direct"]; ok {
		t.Error("direct dep with no scope signal should be omitted")
	}
}
