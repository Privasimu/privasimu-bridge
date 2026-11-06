package agent

// Schemas per source (contract P-4; agent protocol revision 5, proposal). The agent reports,
// for each database source, the schema names its account can see (Oracle: the owners), so
// that the platform can offer a choice per source; a scan_database job may then narrow the
// scan to the chosen schemas (option schemas). Only names leave the agent.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/dbsource"
	"github.com/privasimu/bridge/internal/secrets"
)

const (
	// schemasFile keeps the lists between restarts, so a restart does not withdraw them
	// from the platform until the databases are read again.
	schemasFile = "agent-schemas.json"
	// The platforms' limits (contract P4-L1): at most 200 names per inventory entry, each of 1
	// to 128 characters, and 32 768 bytes of names in one inventory.
	maxSchemasPerSource = 200
	maxSchemaChars      = 128
	maxSchemaBytes      = 32 << 10
	// maxSchemaOption is the most names a job's option schemas may hold.
	maxSchemaOption = 100
	// maxSchemasKept bounds what is kept per source (the database may have more).
	maxSchemasKept = 1000
	// capSchemasPartial marks an inventory entry whose list was cut to fit the limits.
	capSchemasPartial = "schemas_partial"
	// discoverTimeout bounds reading one source's schemas when the agent starts.
	discoverTimeout = 2 * time.Minute
)

// schemaList is what a database answered: the names (sorted, unique, at most
// maxSchemasKept) and whether it had more.
type schemaList struct {
	Names []string `json:"names"`
	More  bool     `json:"more,omitempty"`
}

type schemaState struct {
	Sources map[string]schemaList `json:"sources"`
}

// loadSchemaLists reads the lists an earlier run stored; a missing or damaged file is no list.
func loadSchemaLists(stateDir string) map[string]schemaList {
	out := map[string]schemaList{}
	data, err := os.ReadFile(filepath.Join(stateDir, schemasFile)) // #nosec G304 -- inside the configured state directory
	if err != nil {
		return out
	}
	var st schemaState
	if json.Unmarshal(data, &st) != nil {
		return out
	}
	for id, l := range st.Sources {
		out[id] = l
	}
	return out
}

// schemaName is the label rule for a schema name (contract P4-L1): 1 to 128 characters of
// valid UTF-8 without a C0 control character or DEL.
func schemaName(s string) bool {
	if s == "" || !utf8.ValidString(s) || utf8.RuneCountInString(s) > maxSchemaChars {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// sortedNames returns the names sorted by byte and without duplicates.
func sortedNames(names []string) []string {
	out := append([]string{}, names...)
	sort.Strings(out)
	return slices.Compact(out)
}

// offeredSchemas is the list the inventory reports for a source and whether it is
// incomplete: the database's list narrowed by the allow-list (compared without case; the
// database's spelling is kept), or, before the database was read, the allow-list itself.
// Names outside the label rule cannot be chosen and are left out. ok is false when there is
// no list to report.
func offeredSchemas(src *config.SourceConfig, read schemaList, known bool) (names []string, partial, ok bool) {
	if !dbsource.HasSchemas(src.Engine) {
		return nil, false, false
	}
	switch {
	case known:
		names, partial = []string{}, read.More
		for _, n := range read.Names {
			if !schemaAllowed(src, n) {
				continue
			}
			if !schemaName(n) {
				partial = true
				continue
			}
			names = append(names, n)
		}
	case len(src.Schemas) > 0:
		names = []string{}
		for _, n := range src.Schemas {
			if schemaName(n) {
				names = append(names, n)
			}
		}
	default:
		return nil, false, false
	}
	return sortedNames(names), partial, true
}

// schemaAllowed reports whether the source's allow-list admits a schema (every schema when
// it has none).
func schemaAllowed(src *config.SourceConfig, schema string) bool {
	if len(src.Schemas) == 0 {
		return true
	}
	for _, s := range src.Schemas {
		if strings.EqualFold(s, schema) {
			return true
		}
	}
	return false
}

// addSchemas puts the offered lists into an inventory sorted by id, within the platforms'
// limits: at most maxSchemasPerSource names per entry and maxSchemaBytes of names in all,
// given out in inventory order. A cut list gets the capability schemas_partial.
func addSchemas(cfg *config.Config, out []Source, lists map[string]schemaList) {
	budget := maxSchemaBytes
	for i := range out {
		if out[i].Kind != "database" {
			continue
		}
		src, ok := cfg.Source(out[i].ID)
		if !ok {
			continue
		}
		read, known := lists[out[i].ID]
		names, partial, ok := offeredSchemas(src, read, known)
		if !ok {
			continue
		}
		kept := names[:0:0]
		for _, n := range names {
			if len(kept) == maxSchemasPerSource || len(n) > budget {
				partial = true
				break
			}
			kept = append(kept, n)
			budget -= len(n)
		}
		out[i].Schemas = kept
		if partial && len(out[i].Capabilities) < 16 {
			out[i].Capabilities = append(out[i].Capabilities, capSchemasPartial)
		}
	}
}

// schemaLists returns a copy of the lists read so far.
func (a *Agent) schemaLists() map[string]schemaList {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[string]schemaList, len(a.schemas))
	for id, l := range a.schemas {
		out[id] = l
	}
	return out
}

// storeSchemas keeps a source's list when it changed, and writes the state file; the next
// poll then carries a new inventory digest, and the platform asks for the inventory.
func (a *Agent) storeSchemas(id string, names []string) {
	l := schemaList{Names: sortedNames(names)}
	if len(l.Names) > maxSchemasKept {
		l.Names, l.More = l.Names[:maxSchemasKept], true
	}
	// schemaSave is held from the change to the write, so the file always ends with the
	// newest lists when two refreshes meet.
	a.schemaSave.Lock()
	defer a.schemaSave.Unlock()
	a.mu.Lock()
	old, had := a.schemas[id]
	if had && old.More == l.More && slices.Equal(old.Names, l.Names) {
		a.mu.Unlock()
		return
	}
	a.schemas[id] = l
	raw, _ := json.MarshalIndent(schemaState{Sources: a.schemas}, "", "  ")
	a.mu.Unlock()
	if err := secrets.WriteFileAtomic(filepath.Join(a.stateDir, schemasFile), raw, 0o600); err != nil {
		a.log.Warn("the schema lists could not be stored; they are read again at the next start", "error", err.Error())
	}
	a.log.Info("schema list of a source changed; the inventory follows on the next poll", "source", id, "schemas", len(l.Names))
}

// refreshSchemas reads a source's schemas through an open connection (after a successful
// test or scan). A failure keeps the last list.
func (a *Agent) refreshSchemas(ctx context.Context, src *config.SourceConfig, conn dbsource.Conn) {
	sl, ok := conn.(dbsource.SchemaLister)
	if !ok || !dbsource.HasSchemas(src.Engine) {
		return
	}
	names, err := sl.ListSchemas(ctx)
	if err != nil {
		if !errors.Is(err, dbsource.ErrSchemasUnsupported) && ctx.Err() == nil {
			a.log.Warn("the schemas of a source could not be read; the inventory keeps the last list", "source", src.ID,
				"kind", dbsource.KindOf(err), "error", errMessage(err))
		}
		return
	}
	a.storeSchemas(src.ID, names)
}

// discoverSchemas reads the schemas of every database source once when the agent starts,
// one source at a time, for the engines that report a list. It does nothing when the agent
// may neither test nor scan databases.
func (a *Agent) discoverSchemas(ctx context.Context) {
	if !a.cfg.Agent.JobAllowed(JobScanDatabase) && !a.cfg.Agent.JobAllowed(JobTestSource) {
		return
	}
	for i := range a.cfg.Sources {
		src := &a.cfg.Sources[i]
		if ctx.Err() != nil {
			return
		}
		if !dbsource.ListsSchemas(src.Engine) {
			continue
		}
		t, err := dbsource.FromSource(src, a.resolver.Resolve)
		if err != nil {
			continue // check and the jobs report a missing secret
		}
		sctx, cancel := context.WithTimeout(ctx, discoverTimeout)
		conn, err := a.open(sctx, t)
		if err != nil {
			if ctx.Err() == nil {
				a.log.Warn("the schemas of a source could not be read when the agent started; the inventory keeps the last list",
					"source", src.ID, "kind", dbsource.KindOf(err), "error", errMessage(err))
			}
			cancel()
			continue
		}
		a.refreshSchemas(sctx, src, conn)
		_ = conn.Close()
		cancel()
	}
}

// chosenSchemas checks the option schemas of a scan_database job and returns the schemas to
// scan: 1 to 100 names of the label rule, each admitted by the source's allow-list, for an
// engine with schemas. Duplicates are dropped. Anything else is invalid_options.
func chosenSchemas(src *config.SourceConfig, names []string) ([]string, error) {
	if !dbsource.HasSchemas(src.Engine) || len(names) > maxSchemaOption {
		return nil, failure("config", FailInvalidOptions, "accept", false)
	}
	for _, n := range names {
		if !schemaName(n) || !schemaAllowed(src, n) {
			return nil, failure("config", FailInvalidOptions, "accept", false)
		}
	}
	return sortedNames(names), nil
}
