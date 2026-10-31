package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/privasimu/bridge/internal/apikey"
	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/i18n"
	"github.com/privasimu/bridge/internal/secrets"
)

// cmdKey manages the API keys of mode A. Keys are written to bridge.yaml as hashes; the
// key itself is printed once.
func (a *app) cmdKey(args []string) error {
	action, rest, err := a.subcommand(args, "cli.key.usage", "create", "list", "revoke")
	if err != nil {
		return err
	}
	switch action {
	case "create":
		fs := newFlags("key create")
		expires := fs.String("expires", "", "")
		if err := parseFlags(a, fs, rest, "cli.key.usage"); err != nil {
			return err
		}
		if *expires != "" {
			if _, err := time.Parse("2006-01-02", *expires); err != nil {
				return errors.New(i18n.T("config.key_expires", "--expires"))
			}
		}
		key, id, hash, err := apikey.Generate()
		if err != nil {
			return err
		}
		entry := config.APIKey{ID: id, Hash: hash, Created: time.Now().UTC().Format("2006-01-02"), Expires: *expires}
		if err := a.editKeys(func(keys *yaml.Node) error { return appendKey(keys, entry) }); err != nil {
			return err
		}
		a.printf("cli.key.created", id)
		fmt.Fprintf(a.stdout, "\n    %s\n\n", key)
		a.printf("cli.key.restart")
		return nil
	case "list":
		cfg, err := a.load()
		if err != nil {
			return err
		}
		for _, k := range cfg.Server.APIKeys {
			state := i18n.T("cli.key.active")
			if k.Disabled {
				state = i18n.T("cli.key.revoked")
			}
			fmt.Fprintf(a.stdout, "%-14s %-10s %-10s %s\n", k.ID, k.Created, k.Expires, state)
		}
		return nil
	default:
		if len(rest) != 1 {
			fmt.Fprintln(a.stderr, i18n.T("cli.key.usage"))
			return errUsage
		}
		found := false
		err := a.editKeys(func(keys *yaml.Node) error {
			for _, item := range keys.Content {
				if mappingValue(item, "id") == rest[0] {
					setMapping(item, "disabled", "true", "!!bool")
					found = true
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		if !found {
			return errors.New(i18n.T("cli.key.not_found", rest[0]))
		}
		a.printf("cli.key.revoked_done", rest[0])
		a.printf("cli.key.restart")
		return nil
	}
}

// editKeys changes server.api_keys in bridge.yaml, keeping comments, and checks that the
// result still loads.
func (a *app) editKeys(edit func(keys *yaml.Node) error) error {
	data, err := os.ReadFile(a.configPath)
	if err != nil {
		return err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return err
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return errors.New("bridge.yaml is not a mapping")
	}
	server := child(doc.Content[0], "server", yaml.MappingNode)
	keys := child(server, "api_keys", yaml.SequenceNode)
	if err := edit(keys); err != nil {
		return err
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return err
	}
	_ = enc.Close()
	if _, err := config.Parse(buf.Bytes()); err != nil {
		return err
	}
	return secrets.WriteFileAtomic(a.configPath, buf.Bytes(), 0o640)
}

// child returns the value of key in a mapping, creating it with the given kind.
func child(m *yaml.Node, key string, kind yaml.Kind) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			v := m.Content[i+1]
			if v.Kind != kind {
				v.Kind, v.Tag, v.Value, v.Content, v.Style = kind, "", "", nil, 0
			}
			return v
		}
	}
	k := &yaml.Node{Kind: yaml.ScalarNode, Value: key}
	v := &yaml.Node{Kind: kind}
	m.Content = append(m.Content, k, v)
	return v
}

func mappingValue(m *yaml.Node, key string) string {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1].Value
		}
	}
	return ""
}

func setMapping(m *yaml.Node, key, value, tag string) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1].Value, m.Content[i+1].Tag = value, tag
			return
		}
	}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: key}, &yaml.Node{Kind: yaml.ScalarNode, Value: value, Tag: tag})
}

func appendKey(keys *yaml.Node, k config.APIKey) error {
	item := &yaml.Node{Kind: yaml.MappingNode}
	setMapping(item, "id", k.ID, "!!str")
	setMapping(item, "hash", k.Hash, "!!str")
	setMapping(item, "created", k.Created, "!!str")
	if k.Expires != "" {
		setMapping(item, "expires", k.Expires, "!!str")
	}
	keys.Style = 0 // block style, also when the list was written as []
	keys.Content = append(keys.Content, item)
	return nil
}
