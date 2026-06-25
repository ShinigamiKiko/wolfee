package output

import (
	"reflect"
	"sort"
	"strings"
)

func anyOriginAttributed(components reflect.Value) bool {
	if !components.IsValid() {
		return false
	}
	for i := 0; i < components.Len(); i++ {
		switch stringField(components.Index(i), "Origin") {
		case "base", "app", "image":
			return true
		}
	}
	return false
}

func anyNonOSComponent(components reflect.Value) bool {
	if !components.IsValid() {
		return false
	}
	for i := 0; i < components.Len(); i++ {
		switch strings.ToLower(stringField(components.Index(i), "System")) {
		case "deb", "apk", "rpm", "":

		default:
			return true
		}
	}
	return false
}

func anyLayerDigest(components reflect.Value) bool {
	if !components.IsValid() {
		return false
	}
	for i := 0; i < components.Len(); i++ {
		if stringField(components.Index(i), "LayerDigest") != "" {
			return true
		}
	}
	return false
}

type layerSummary struct {
	digest    string
	createdBy string
	pkgs      int
	worst     string
	rank      int
}

func collectLayerSummary(components reflect.Value) []layerSummary {
	if !components.IsValid() {
		return nil
	}
	by := map[string]*layerSummary{}
	for i := 0; i < components.Len(); i++ {
		c := components.Index(i)
		dig := stringField(c, "LayerDigest")
		if dig == "" {
			continue
		}
		s, ok := by[dig]
		if !ok {
			s = &layerSummary{digest: dig, createdBy: stringField(c, "LayerCreatedBy")}
			by[dig] = s
		} else if s.createdBy == "" {
			s.createdBy = stringField(c, "LayerCreatedBy")
		}
		s.pkgs++
		if r := rankComponent(c); r > s.rank {
			s.rank = r
			s.worst = stringField(c, "TopSeverity")
			if boolNested(c, "Malware", "Found") {
				s.worst = "CRITICAL"
			}
		}
	}
	out := make([]layerSummary, 0, len(by))
	for _, s := range by {
		out = append(out, *s)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].rank != out[j].rank {
			return out[i].rank > out[j].rank
		}
		return out[i].pkgs > out[j].pkgs
	})
	return out
}

func trimCreatedBy(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	for _, pfx := range []string{
		"/bin/sh -c #(nop) ",
		"/bin/sh -c #(nop)",
		"/bin/sh -c ",
	} {
		if strings.HasPrefix(s, pfx) {
			s = strings.TrimSpace(s[len(pfx):])
			break
		}
	}
	if len(s) > 80 {
		s = s[:77] + "..."
	}
	return s
}

func originLabel(system, origin string, transitive bool) string {
	osType := ""
	switch strings.ToLower(strings.TrimSpace(system)) {
	case "deb", "apk", "rpm":
		osType = strings.ToUpper(strings.TrimSpace(system))
	}
	if osType != "" {

		if origin == "image" {
			return osType + "(image)"
		}
		return osType
	}

	switch origin {
	case "base":
		return "BASE"
	case "app":
		if transitive {
			return "APP(T)"
		}
		return "APP"
	case "image":
		return "LIB(image)"
	default:
		return "-"
	}
}

func shortDigest(d string) string {
	if d == "" {
		return ""
	}
	d = strings.TrimPrefix(d, "sha256:")
	if len(d) > 12 {
		d = d[:12]
	}
	return d
}

func countComponentErrors(components reflect.Value) int {
	if !components.IsValid() {
		return 0
	}
	n := 0
	for i := 0; i < components.Len(); i++ {
		if e := stringField(components.Index(i), "Error"); e != "" {
			n++
		}
	}
	return n
}
