package nlp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/detect"
)

// fakeService finds names and NIKs like a token-classification model: character offsets,
// scores, and the entity text in "word" (which the client must not need).
func fakeService(t *testing.T, calls *atomic.Int32, fail *atomic.Bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var req struct {
			Text string `json:"text"`
		}
		if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&req) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		type ent struct {
			Group string  `json:"entity_group"`
			Word  string  `json:"word"`
			Score float64 `json:"score"`
			Start int     `json:"start"`
			End   int     `json:"end"`
		}
		var out []ent
		runes := []rune(req.Text)
		text := string(runes)
		for _, word := range []string{"Budi Contoh", "Siti Aminah"} {
			for from := 0; ; {
				i := strings.Index(text[from:], word)
				if i < 0 {
					break
				}
				start := utf8.RuneCountInString(text[:from+i])
				out = append(out, ent{Group: "NAME", Word: word, Score: 0.97, Start: start, End: start + utf8.RuneCountInString(word)})
				from += i + len(word)
			}
		}
		if i := strings.Index(text, "3171012303900001"); i >= 0 {
			start := utf8.RuneCountInString(text[:i])
			out = append(out, ent{Group: "NIK", Word: "3171012303900001", Score: 0.99, Start: start, End: start + 16})
		}
		if strings.Contains(text, "Jalan") {
			out = append(out, ent{Group: "ADDRESS", Word: "Jalan", Score: 0.5, Start: 0, End: 5}) // below min_score
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"entities": out})
	}))
}

func client(t *testing.T, endpoint string, maxBytes int) *Client {
	t.Helper()
	cfg, err := config.Parse([]byte("detection:\n  nlp: {enabled: true, endpoint: \"" + endpoint + "\", timeout: 2s}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if maxBytes > 0 {
		cfg.Detection.NLP.MaxBytes = config.ByteSize(maxBytes)
	}
	c, err := New(cfg, nil)
	if err != nil || c == nil {
		t.Fatalf("%v %v", c, err)
	}
	return c
}

func TestCountMapsEntitiesToTheirTexts(t *testing.T) {
	var calls atomic.Int32
	var fail atomic.Bool
	srv := fakeService(t, &calls, &fail)
	defer srv.Close()
	c := client(t, srv.URL+"/", 0)
	texts := []string{
		"catatan: nasabah Budi Contoh menelepon",       // a name
		"ñandú é — tidak ada nama di sini sama sekali", // non-ASCII characters before the next text
		"Siti Aminah dan Budi Contoh, NIK 3171012303900001, Jalan Contoh",
	}
	found, err := c.Count(context.Background(), texts)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 3 || found[0][detect.PersonName] != 1 || found[1] != nil || found[2][detect.PersonName] != 2 {
		t.Fatalf("%v", found)
	}
	// NIK is the validators' (never the model's); the address scored below min_score.
	if found[2][detect.NIK] != 0 || found[2][detect.Address] != 0 {
		t.Fatalf("%v", found[2])
	}
}

func TestCountSendsAtMostMaxBytes(t *testing.T) {
	var got atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Text string `json:"text"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		got.Store(int64(len(req.Text)))
		_, _ = w.Write([]byte(`{"entities":[]}`))
	}))
	defer srv.Close()
	c := client(t, srv.URL, 1024)
	long := strings.Repeat("é", 2000) // 4000 bytes
	if _, err := c.Count(context.Background(), []string{long, long}); err != nil {
		t.Fatal(err)
	}
	if got.Load() > 1024 || got.Load() < 1000 {
		t.Fatalf("sent %d bytes, want at most 1024", got.Load())
	}
}

func TestAFailingServiceIsLeftAloneForAMinute(t *testing.T) {
	var calls atomic.Int32
	var fail atomic.Bool
	fail.Store(true)
	srv := fakeService(t, &calls, &fail)
	defer srv.Close()
	c := client(t, srv.URL, 0)
	now := time.Now()
	c.now = func() time.Time { return now }
	if _, err := c.Count(context.Background(), []string{"Budi Contoh"}); err == nil {
		t.Fatal("a failing service must report an error")
	}
	if _, err := c.Count(context.Background(), []string{"Budi Contoh"}); !errors.Is(err, ErrUnavailable) || calls.Load() != 1 {
		t.Fatalf("the service must be left alone: %v, %d calls", err, calls.Load())
	}
	fail.Store(false)
	now = now.Add(2 * time.Minute)
	if found, err := c.Count(context.Background(), []string{"Budi Contoh"}); err != nil || found[0][detect.PersonName] != 1 {
		t.Fatalf("after the pause: %v %v", found, err)
	}
}

func TestOnlyLocalAndPrivateAddressesAreReached(t *testing.T) {
	c := client(t, "http://203.0.113.10:8333/", 0)
	if _, err := c.Count(context.Background(), []string{"Budi Contoh"}); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("a public address must be refused before connecting: %v", err)
	}
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://203.0.113.10/", http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	c = client(t, redirect.URL, 0)
	if _, err := c.Count(context.Background(), []string{"Budi Contoh"}); err == nil {
		t.Fatal("a redirect must not be followed")
	}
}

func TestOffIsNil(t *testing.T) {
	cfg, _ := config.Parse([]byte("{}"))
	if c, err := New(cfg, nil); c != nil || err != nil {
		t.Fatalf("%v %v", c, err)
	}
}
