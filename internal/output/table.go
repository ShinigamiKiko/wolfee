package output

import (
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"
	"text/tabwriter"
)

type Table struct {
	NoColor bool
}

func (t Table) Render(w io.Writer, report any) error {
	v := reflect.Indirect(reflect.ValueOf(report))
	if v.Kind() != reflect.Struct {
		return fmt.Errorf("table: unexpected report type %T", report)
	}
	totals := v.FieldByName("Totals")
	source := stringField(v, "Source")
	components := v.FieldByName("Components")
	if !components.IsValid() {
		return nil
	}

	useColor := !t.NoColor && os.Getenv("NO_COLOR") == ""
	c := newColors(useColor)

	fmt.Fprintln(w)
	fmt.Fprintln(w, c.bold("┌─ wolfee ─ vulnerability scan ─────────────────────────────"))
	if source != "" {
		fmt.Fprintln(w, c.bold("│ ")+"source: "+source)
	}
	if ts := stringField(v, "GeneratedAt"); ts != "" {
		fmt.Fprintln(w, c.bold("│ ")+"scanned: "+ts)
	}
	fmt.Fprintln(w, c.bold("└────────────────────────────────────────────────────────────"))
	fmt.Fprintln(w)

	fmt.Fprintln(w, c.bold("Summary"))
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "  Components scanned\t%d\n", intField(totals, "Scanned"))

	if direct, transitive := intField(totals, "Direct"), intField(totals, "Transitive"); direct+transitive > 0 {
		fmt.Fprintf(tw, "  Direct dependencies\t%d\n", direct)
		fmt.Fprintf(tw, "  Transitive dependencies\t%d\n", transitive)
	}
	if skipped := intField(totals, "Skipped"); skipped > 0 {
		fmt.Fprintf(tw, "  Components skipped (no purl)\t%d\n", skipped)
	}
	fmt.Fprintf(tw, "  With vulnerabilities\t%d\n", intField(totals, "WithVulns"))

	reach := intField(totals, "Reachable")
	unreach := intField(totals, "Unreachable")
	reachUnk := intField(totals, "ReachUnknown")
	pkgUsed := intField(totals, "PackageUsed")
	pkgUnused := intField(totals, "PackageUnused")
	if reach+unreach+reachUnk > 0 {
		line := func(label string, n int, col func(string) string) {
			if n > 0 {
				fmt.Fprintf(tw, "  %s\t%s\n", label, col(fmt.Sprintf("%d", n)))
			}
		}
		line("CVEs called (reachable)", reach, c.crit)
		line("CVEs not called (unreachable)", unreach, c.green)
		line("CVEs undecided (no data)", reachUnk, c.low)
	}
	if pkgUsed+pkgUnused > 0 {
		line := func(label string, n int, col func(string) string) {
			if n > 0 {
				fmt.Fprintf(tw, "  %s\t%s\n", label, col(fmt.Sprintf("%d", n)))
			}
		}
		line("Packages imported (in use)", pkgUsed, c.med)
		line("Packages not imported (unused)", pkgUnused, c.low)
	}
	if mal := intField(totals, "Malware"); mal > 0 {
		fmt.Fprintf(tw, "  Malware\t%s\n", c.crit(fmt.Sprintf("%d", mal)))
	}
	if tox := intField(totals, "Toxic"); tox > 0 {
		fmt.Fprintf(tw, "  Toxic packages\t%d\n", tox)
	}
	if kev := intField(totals, "KEV"); kev > 0 {
		fmt.Fprintf(tw, "  In CISA KEV\t%s\n", c.high(fmt.Sprintf("%d", kev)))
	}
	if poc := intField(totals, "PoC"); poc > 0 {
		fmt.Fprintf(tw, "  Public PoC\t%s\n", c.med(fmt.Sprintf("%d", poc)))
	}
	if errCount := countComponentErrors(components); errCount > 0 {
		fmt.Fprintf(tw, "  Components with errors\t%s\n",
			c.high(fmt.Sprintf("%d (use --format json for details)", errCount)))
	}
	fmt.Fprintf(tw, "  Severity\t%s %d\t%s %d\t%s %d\t%s %d\n",
		c.crit("CRIT"), intField(totals, "CRITICAL"),
		c.high("HIGH"), intField(totals, "HIGH"),
		c.med("MED "), intField(totals, "MEDIUM"),
		c.low("LOW "), intField(totals, "LOW"),
	)
	tw.Flush()
	fmt.Fprintln(w)

	type row struct {
		idx  int
		rank int
		val  reflect.Value
	}
	rows := make([]row, 0, components.Len())
	for i := 0; i < components.Len(); i++ {
		comp := components.Index(i)
		rows = append(rows, row{idx: i, rank: rankComponent(comp), val: comp})
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].rank > rows[j].rank })

	const maxRows = 200
	affected := 0
	for _, r := range rows {
		if r.rank > 0 {
			affected++
		}
	}
	if affected == 0 {
		fmt.Fprintln(w, c.green("✓ No vulnerabilities or malware detected"))
		fmt.Fprintln(w)
		return nil
	}

	fmt.Fprintln(w, c.bold("Findings"))
	showLayer := anyLayerDigest(components)
	showLang := anyLanguageRelevance(components)
	fg := &grid{}
	if showLayer {
		header := []string{"PACKAGE", "VERSION", "ECO", "LAYER", "VULNS", "FLAGS", "TOXIC", "ORIGIN"}
		if showLang {
			header = append(header, "LANG")
		}
		fg.add(header...)
	} else {
		header := []string{"PACKAGE", "VERSION", "ECO", "VULNS", "FLAGS", "TOXIC"}
		if showLang {
			header = append(header, "LANG")
		}
		fg.add(header...)
	}
	shown := 0
	for _, r := range rows {
		if r.rank == 0 {
			break
		}
		if shown >= maxRows {
			fg.add(fmt.Sprintf("... (%d more rows omitted; use --format json for full list)", affected-shown))
			break
		}
		comp := r.val

		toxic := ""
		if boolNested(comp, "Toxic", "Found") {
			toxic = "TOXIC"
			if cat := firstToxicCategory(comp); cat != "" {
				toxic = "TOXIC[" + cat + "]"
			}
			toxic = c.high(toxic)
		}
		flags := []string{}
		if boolNested(comp, "Malware", "Found") {
			label := "MALWARE"
			if srcs := malwareSources(comp); srcs != "" {
				label = "MALWARE[" + srcs + "]"
			}
			flags = append(flags, c.crit(label))
		}
		if hasKEV(comp) {
			flags = append(flags, c.high("KEV"))
		}
		if hasPoC(comp) {
			flags = append(flags, c.med("PoC"))
		}
		usage := stringField(comp, "PackageUsage")
		switch usage {
		case "used", "used-transitive":
			usedStr := c.med("used")
			if site := stringField(comp, "ImportSite"); site != "" {
				usedStr += " " + site
			}
			flags = append(flags, usedStr)
		case "unused":
			flags = append(flags, c.green("not-used"))
		}

		transitive := strings.EqualFold(stringField(comp, "Scope"), "optional") || usage == "used-transitive"
		lang := ""
		if showLang {
			relevant, known := relevantField(comp, "Relevant")
			lang = c.lang(
				langLabel(stringField(comp, "System"), stringField(comp, "PURL"), stringField(comp, "Language")),
				relevant, known,
			)
		}
		if showLayer {
			cells := []string{
				stringField(comp, "Name"),
				stringField(comp, "Version"),
				strings.ToLower(stringField(comp, "System")),
				shortDigest(stringField(comp, "LayerDigest")),
				fmt.Sprintf("%d", intField(comp, "VulnCount")),
				strings.Join(flags, " "),
				toxic,
				c.origin(originLabel(stringField(comp, "System"), stringField(comp, "Origin"), transitive)),
			}
			if showLang {
				cells = append(cells, lang)
			}
			fg.add(cells...)
		} else {
			cells := []string{
				stringField(comp, "Name"),
				stringField(comp, "Version"),
				strings.ToLower(stringField(comp, "System")),
				fmt.Sprintf("%d", intField(comp, "VulnCount")),
				strings.Join(flags, " "),
				toxic,
			}
			if showLang {
				cells = append(cells, lang)
			}
			fg.add(cells...)
		}
		shown++
	}
	fg.render(w)

	if showLayer && anyNonOSComponent(components) && !anyOriginAttributed(components) {
		fmt.Fprintln(w, c.low(`  note: ORIGIN "-" = not attributed; pass --scout to tag non-OS packages BASE vs APP`))
	}
	fmt.Fprintln(w)

	if showLayer {
		layers := collectLayerSummary(components)
		if len(layers) > 0 {
			fmt.Fprintln(w, c.bold("Affected layers"))
			lg := &grid{}
			lg.add("LAYER", "PKGS", "WORST", "CREATED BY")
			for _, l := range layers {
				lg.add(shortDigest(l.digest), fmt.Sprintf("%d", l.pkgs), c.sev(l.worst), trimCreatedBy(l.createdBy))
			}
			lg.render(w)
			fmt.Fprintln(w)
		}
	}

	reachRows := collectReachableVulns(components)
	if len(reachRows) > 0 {
		fmt.Fprintln(w, c.bold("Reachable vulnerabilities (called by your code)"))
		rg := &grid{}
		rg.add("SEV", "CVE", "PACKAGE", "CALL SITE")
		for _, r := range reachRows {
			callInfo := r.callSite
			if r.callLine != "" {
				callInfo = r.callLine
				if r.callSite != "" {
					callInfo += " (" + r.callSite + ")"
				}
			}

			displayID := r.cve
			if displayID == "" {
				displayID = r.id
			}
			rg.add(c.sev(r.sev), c.crit(displayID), r.pkg, callInfo)
		}
		rg.render(w)
		fmt.Fprintln(w)
	}

	const maxVulnRows = 200
	top := collectTopVulns(components)
	if len(top) > 0 {
		fmt.Fprintln(w, c.bold("Vulnerabilities"))
		vg := &grid{}

		if showLayer {
			vg.add("SEV", "CVE", "PACKAGE", "EPSS", "FIX", "FLAGS", "ORIGIN")
		} else {
			vg.add("SEV", "CVE", "PACKAGE", "EPSS", "FIX", "FLAGS")
		}
		shown := 0
		for _, t := range top {
			if shown >= maxVulnRows {
				vg.add(fmt.Sprintf("... (%d more - use --format json for full list)", len(top)-shown))
				break
			}
			flags := []string{}
			if t.kev {
				flags = append(flags, c.high("KEV"))
			}
			if t.poc {
				flags = append(flags, c.med("PoC"))
			}

			switch t.reach {
			case "reachable":
				flags = append(flags, c.crit("called"))
			case "unreachable":
				flags = append(flags, c.green("not-called"))
			}
			epss := ""
			if t.epss > 0 {
				epss = fmt.Sprintf("%.2f", t.epss)
			}

			displayID := t.cve
			if displayID == "" {
				displayID = t.id
			}
			if showLayer {
				vg.add(c.sev(t.sev), displayID, t.pkg, epss, t.fix, strings.Join(flags, " "),
					c.origin(originLabel(t.system, t.origin, strings.EqualFold(t.scope, "optional"))))
			} else {
				vg.add(c.sev(t.sev), displayID, t.pkg, epss, t.fix, strings.Join(flags, " "))
			}
			shown++
		}
		vg.render(w)
		fmt.Fprintln(w)
	}

	renderDependencyPaths(w, c, components)

	return nil
}

func renderDependencyPaths(w io.Writer, c colors, components reflect.Value) {
	type row struct {
		pkg   string
		paths [][]string
	}
	var rows []row
	for i := 0; i < components.Len(); i++ {
		comp := components.Index(i)
		vulns := comp.FieldByName("Vulnerabilities")
		if !vulns.IsValid() || vulns.Len() == 0 {
			continue
		}
		paths := stringMatrixField(comp, "DependencyPaths")
		if len(paths) == 0 {
			continue
		}
		rows = append(rows, row{
			pkg:   fmt.Sprintf("%s@%s", stringField(comp, "Name"), stringField(comp, "Version")),
			paths: paths,
		})
	}
	if len(rows) == 0 {
		return
	}
	fmt.Fprintln(w, c.bold("Dependency paths")+c.low("  (* = update this to fix - chain ends at the vulnerable lib)"))
	const maxRows = 50
	sep := c.low(" › ")
	for i, r := range rows {
		if i >= maxRows {
			fmt.Fprintln(w, c.low(fmt.Sprintf("  ... (%d more - use --format json for the full list)", len(rows)-i)))
			break
		}

		_, compVer := splitNameVer(r.pkg)

		fmt.Fprintf(w, "  %s %s\n", r.pkg, c.high("(vuln)"))
		for _, p := range r.paths {
			if len(p) == 0 {
				continue
			}

			hops := append([]string(nil), p...)
			// The chain ends at the vulnerable lib, so pin its last hop to the
			// version that was actually flagged. In --compare the path is grafted
			// from the source SBOM, which can record a different (require-edge)
			// version than the one the image ships - showing that here just looked
			// like an unexplained second version of the same package.
			if compVer != "" {
				last := len(hops) - 1
				if n, _ := splitNameVer(hops[last]); n != "" {
					hops[last] = n + "@" + compVer
				}
			}
			hops[0] = c.crit("*") + hops[0]
			fmt.Fprintf(w, "    %s\n", strings.Join(hops, sep))
		}
	}
	fmt.Fprintln(w)
}
