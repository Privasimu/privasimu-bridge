package dbsource

import (
	"context"
	"net"
	"sort"
	"strconv"
	"strings"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"

	"github.com/privasimu/bridge/internal/config"
)

// fieldDocs is how many documents are read to learn the fields of a collection. MongoDB
// has no schema catalog, so field names can only be learned from documents; the values
// are not examined unless sampling is enabled.
const fieldDocs = 100

const (
	maxFieldDepth = 5
	maxFields     = 1000
)

type mongoConn struct {
	client  *mongo.Client
	db      *mongo.Database
	t       Target
	version string
	tls     *bool
}

func openMongo(ctx context.Context, t Target) (Conn, error) {
	opts := options.Client()
	if t.URI.Reveal() != "" {
		opts.ApplyURI(t.URI.Reveal())
	} else {
		opts.SetHosts([]string{net.JoinHostPort(t.Host, strconv.Itoa(t.Port))})
		source := t.AuthSource
		if source == "" {
			source = t.Database
		}
		opts.SetAuth(options.Credential{Username: t.Username, Password: t.Password.Reveal(), AuthSource: source})
	}
	opts.SetAppName("privasimu-bridge")
	opts.SetConnectTimeout(t.Timeout)
	opts.SetServerSelectionTimeout(t.Timeout)
	opts.SetTimeout(t.Timeout)
	opts.SetMaxPoolSize(uint64(t.MaxOpen))
	// Reading from a secondary keeps the load off the primary.
	opts.SetReadPreference(readpref.SecondaryPreferred())
	var tlsOn *bool
	switch t.TLS.Mode {
	case config.DBTLSDisable, "":
		// TLS may still be switched on by the connection string (tls=true).
	default:
		tlsCfg, err := t.TLS.TLSConfig(t.Host)
		if err != nil {
			return nil, err
		}
		opts.SetTLSConfig(tlsCfg)
		on := true
		tlsOn = &on
	}
	if t.Dial != nil {
		opts.SetDialer(ctxDialer{t.Dial})
	}
	if err := opts.Validate(); err != nil {
		// The driver error can quote the connection string; never show it.
		return nil, &Error{Kind: KindConfig, Op: "config", Safe: false}
	}
	client, err := mongo.Connect(opts)
	if err != nil {
		return nil, &Error{Kind: KindConfig, Op: "connect", Safe: false}
	}
	pctx, cancel := context.WithTimeout(ctx, t.Timeout)
	defer cancel()
	if err := client.Ping(pctx, readpref.SecondaryPreferred()); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, wrap("connect", err, false)
	}
	c := &mongoConn{client: client, db: client.Database(t.Database), t: t, tls: tlsOn}
	var info struct {
		Version string `bson:"version"`
	}
	if err := c.db.RunCommand(pctx, bson.D{{Key: "buildInfo", Value: 1}}).Decode(&info); err == nil && info.Version != "" {
		c.version = "MongoDB " + info.Version
	}
	return c, nil
}

func (c *mongoConn) Engine() string                       { return "mongodb" }
func (c *mongoConn) ServerVersion(context.Context) string { return c.version }
func (c *mongoConn) DefaultSchema() string                { return c.t.Database }
func (c *mongoConn) TLSInUse() *bool                      { return c.tls }
func (c *mongoConn) Close() error                         { return c.client.Disconnect(context.Background()) }

func (c *mongoConn) ListTables(ctx context.Context, _ string) ([]Table, error) {
	qctx, cancel := context.WithTimeout(ctx, c.t.Timeout)
	defer cancel()
	names, err := c.db.ListCollectionNames(qctx, bson.D{{Key: "type", Value: "collection"}})
	if err != nil {
		return nil, wrap("list collections", err, true)
	}
	sort.Strings(names)
	out := make([]Table, 0, len(names))
	for _, n := range names {
		if strings.HasPrefix(n, "system.") || !validName(n) {
			continue
		}
		out = append(out, Table{Schema: c.t.Database, Name: n, Ref: n})
	}
	return out, nil
}

func (c *mongoConn) FindTable(ctx context.Context, ref, _ string) (Table, bool, error) {
	if !validName(ref) || strings.HasPrefix(ref, "system.") {
		return Table{}, false, nil
	}
	qctx, cancel := context.WithTimeout(ctx, c.t.Timeout)
	defer cancel()
	names, err := c.db.ListCollectionNames(qctx, bson.D{{Key: "name", Value: ref}, {Key: "type", Value: "collection"}})
	if err != nil {
		return Table{}, false, wrap("find collection", err, true)
	}
	if len(names) == 0 {
		return Table{}, false, nil
	}
	t := Table{Schema: c.t.Database, Name: ref, Ref: ref}
	if n, err := c.db.Collection(ref).EstimatedDocumentCount(qctx); err == nil {
		v := n
		t.RowEstimate = &v
	}
	return t, true, nil
}

// readDocs reads up to n documents and passes each one to fn.
func (c *mongoConn) readDocs(ctx context.Context, t Table, n int, fn func(bson.Raw)) error {
	qctx, cancel := context.WithTimeout(ctx, c.t.Timeout)
	defer cancel()
	cur, err := c.db.Collection(t.Name).Find(qctx, bson.D{}, options.Find().SetLimit(int64(n)).SetBatchSize(int32(min(n, 1000))))
	if err != nil {
		return err
	}
	defer cur.Close(context.Background())
	for cur.Next(qctx) {
		fn(cur.Current)
	}
	return cur.Err()
}

// flatten walks a document and reports every scalar under its dotted path; values in
// arrays are reported under the array's path.
func flatten(prefix string, doc bson.Raw, depth int, fn func(path string, v bson.RawValue)) {
	elems, _ := doc.Elements()
	for _, e := range elems {
		path := e.Key()
		if prefix != "" {
			path = prefix + "." + path
		}
		v := e.Value()
		switch v.Type {
		case bson.TypeEmbeddedDocument:
			if sub, ok := v.DocumentOK(); ok && depth < maxFieldDepth {
				flatten(path, sub, depth+1, fn)
				continue
			}
			fn(path, v)
		case bson.TypeArray:
			arr, ok := v.ArrayOK()
			if !ok {
				continue
			}
			vals, _ := arr.Values()
			for _, av := range vals {
				if sub, ok := av.DocumentOK(); ok && depth < maxFieldDepth {
					flatten(path, sub, depth+1, fn)
				} else {
					fn(path, av)
				}
			}
		default:
			fn(path, v)
		}
	}
}

func mongoSampleable(t bson.Type) bool {
	return t == bson.TypeString || t == bson.TypeInt64 || t == bson.TypeDecimal128
}

func (c *mongoConn) Columns(ctx context.Context, t Table) ([]Column, error) {
	type field struct {
		typ   bson.Type
		count int
	}
	fields := map[string]*field{}
	var order []string
	docs := 0
	err := c.readDocs(ctx, t, fieldDocs, func(doc bson.Raw) {
		docs++
		seen := map[string]bool{}
		flatten("", doc, 0, func(path string, v bson.RawValue) {
			f, ok := fields[path]
			if !ok {
				if len(fields) >= maxFields || !validName(path) {
					return
				}
				f = &field{}
				fields[path] = f
				order = append(order, path)
			}
			if f.typ == 0 && v.Type != bson.TypeNull {
				f.typ = v.Type
			}
			if !seen[path] {
				seen[path] = true
				f.count++
			}
		})
	})
	if err != nil {
		return nil, wrap("columns", err, true)
	}
	out := make([]Column, 0, len(order))
	for _, path := range order {
		f := fields[path]
		nullable := f.count < docs
		typ := "null"
		if f.typ != 0 {
			typ = strings.ToLower(f.typ.String())
		}
		out = append(out, Column{Name: path, DataType: typ, Nullable: &nullable, Sampleable: mongoSampleable(f.typ)})
	}
	return out, nil
}

func (c *mongoConn) Sample(ctx context.Context, t Table, cols []Column, rows int, visit func(int, string, bool)) error {
	index := map[string]int{}
	for i, col := range cols {
		if col.Sampleable {
			index[col.Name] = i
		}
	}
	if len(index) == 0 || rows <= 0 {
		return nil
	}
	err := c.readDocs(ctx, t, rows, func(doc bson.Raw) {
		flatten("", doc, 0, func(path string, v bson.RawValue) {
			i, ok := index[path]
			if !ok {
				return
			}
			switch v.Type {
			case bson.TypeString:
				s, _ := v.StringValueOK()
				visit(i, s, false)
			case bson.TypeInt64:
				n, _ := v.Int64OK()
				visit(i, strconv.FormatInt(n, 10), false)
			case bson.TypeDecimal128:
				d, _ := v.Decimal128OK()
				visit(i, d.String(), false)
			case bson.TypeNull:
				visit(i, "", true)
			}
		})
	})
	if err != nil {
		return wrap("sample", err, false)
	}
	return nil
}
