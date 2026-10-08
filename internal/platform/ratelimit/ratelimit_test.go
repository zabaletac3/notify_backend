package ratelimit_test

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zabaletac3/notify_backend/internal/platform/ratelimit"
	"github.com/zabaletac3/notify_backend/internal/platform/testdb"
)

var (
	ctx    = context.Background()
	pepper = []byte("0123456789abcdef0123456789abcdef-pepper")
	rule   = ratelimit.Rule{Max: 3, Window: time.Minute, Block: 10 * time.Minute}
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }
func newLimiter(t *testing.T) (*ratelimit.Limiter, *clock, *testdb.DB) {
	t.Helper()
	db := testdb.New(t)
	c := &clock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	l := ratelimit.New(db.App, pepper)
	l.Now = c.now
	return l, c, db
}

func TestFailBlocksAtMaxAndUnblocks(t *testing.T) {
	l, c, _ := newLimiter(t)
	key := l.Key("login", "ana@example.com", "1.2.3.4")
	for i := 1; i < rule.Max; i++ {
		if r, err := l.Fail(ctx, key, rule); err != nil || !r.Allowed {
			t.Fatalf("fallo %d: %+v %v", i, r, err)
		}
	}
	r, err := l.Fail(ctx, key, rule)
	if err != nil || r.Allowed || r.RetryAfter != 10*time.Minute {
		t.Fatalf("el fallo %d debía bloquear 10 min: %+v %v", rule.Max, r, err)
	}
	if b, _ := l.Blocked(ctx, key); b.Allowed || b.RetryAfter != 10*time.Minute {
		t.Fatalf("Blocked: %+v", b)
	}
	c.add(9 * time.Minute)
	if b, _ := l.Blocked(ctx, key); b.Allowed || b.RetryAfter != time.Minute {
		t.Fatalf("a los 9 min sigue bloqueado: %+v", b)
	}
	c.add(2 * time.Minute)
	if b, _ := l.Blocked(ctx, key); !b.Allowed {
		t.Fatalf("tras el bloqueo debe permitir: %+v", b)
	}
	if r, _ := l.Fail(ctx, key, rule); !r.Allowed {
		t.Fatalf("el primer fallo tras el bloqueo debe contarse como permitido: %+v", r)
	}
}

func TestBlockedAttemptsDoNotExtendOrCount(t *testing.T) {
	l, c, _ := newLimiter(t)
	key := l.Key("login", "a")
	for i := 0; i < rule.Max; i++ {
		_, _ = l.Fail(ctx, key, rule)
	}
	c.add(5 * time.Minute)
	r, _ := l.Fail(ctx, key, rule)
	if r.Allowed || r.RetryAfter != 5*time.Minute {
		t.Fatalf("un intento bloqueado no debe alargar el bloqueo: %+v", r)
	}
}

func TestProgressiveBlockDoubles(t *testing.T) {
	l, c, _ := newLimiter(t)
	key := l.Key("login", "a")
	want := []time.Duration{10 * time.Minute, 20 * time.Minute, 40 * time.Minute}
	for round, w := range want {
		var last ratelimit.Result
		for i := 0; i < rule.Max; i++ {
			last, _ = l.Fail(ctx, key, rule)
		}
		if last.Allowed || last.RetryAfter != w {
			t.Fatalf("ronda %d: esperaba %v, fue %+v", round, w, last)
		}
		c.add(w + time.Second)
	}
}

func TestBlockIsCappedAt24h(t *testing.T) {
	l, c, _ := newLimiter(t)
	key := l.Key("login", "a")
	big := ratelimit.Rule{Max: 1, Window: time.Minute, Block: 8 * time.Hour}
	var last ratelimit.Result
	for i := 0; i < 5; i++ {
		last, _ = l.Fail(ctx, key, big)
		c.add(last.RetryAfter + time.Second)
	}
	if last.RetryAfter != 24*time.Hour {
		t.Fatalf("el bloqueo debe topar en 24 h: %v", last.RetryAfter)
	}
}

func TestStrikesDecayAfterADay(t *testing.T) {
	l, c, _ := newLimiter(t)
	key := l.Key("login", "a")
	for i := 0; i < rule.Max; i++ {
		_, _ = l.Fail(ctx, key, rule)
	}
	c.add(48 * time.Hour)
	var last ratelimit.Result
	for i := 0; i < rule.Max; i++ {
		last, _ = l.Fail(ctx, key, rule)
	}
	if last.RetryAfter != 10*time.Minute {
		t.Fatalf("tras un día sin bloqueos debe volver al bloqueo base: %v", last.RetryAfter)
	}
}

func TestWindowExpiryResetsCount(t *testing.T) {
	l, c, _ := newLimiter(t)
	key := l.Key("login", "a")
	for i := 0; i < rule.Max-1; i++ {
		_, _ = l.Fail(ctx, key, rule)
	}
	c.add(2 * time.Minute) // la ventana (1 min) caduca
	for i := 0; i < rule.Max-1; i++ {
		if r, _ := l.Fail(ctx, key, rule); !r.Allowed {
			t.Fatalf("los fallos de una ventana caducada no deben acumularse: %+v", r)
		}
	}
}

func TestTakeAllowsMaxThenDenies(t *testing.T) {
	l, _, _ := newLimiter(t)
	key := l.Key("resend", "ana@example.com")
	for i := 1; i <= rule.Max; i++ {
		if r, err := l.Take(ctx, key, rule); err != nil || !r.Allowed {
			t.Fatalf("intento %d: %+v %v", i, r, err)
		}
	}
	if r, _ := l.Take(ctx, key, rule); r.Allowed || r.RetryAfter != 10*time.Minute {
		t.Fatalf("el intento %d debía denegarse: %+v", rule.Max+1, r)
	}
}

func TestResetClearsEverything(t *testing.T) {
	l, _, _ := newLimiter(t)
	key := l.Key("login", "a")
	for i := 0; i < rule.Max; i++ {
		_, _ = l.Fail(ctx, key, rule)
	}
	if err := l.Reset(ctx, key); err != nil {
		t.Fatal(err)
	}
	if b, _ := l.Blocked(ctx, key); !b.Allowed {
		t.Fatal("Reset no desbloqueó")
	}
	for i := 0; i < rule.Max-1; i++ {
		if r, _ := l.Fail(ctx, key, rule); !r.Allowed {
			t.Fatal("Reset no reinició el contador")
		}
	}
}

func TestKeysAreIndependentAndHashed(t *testing.T) {
	l, _, db := newLimiter(t)
	a, b := l.Key("login", "ana@example.com", "1.2.3.4"), l.Key("login", "luis@example.com", "1.2.3.4")
	if a == b || l.Key("login", "x") == l.Key("otro", "x") {
		t.Fatal("las claves deben depender de sus partes y del tipo")
	}
	for i := 0; i < rule.Max; i++ {
		_, _ = l.Fail(ctx, a, rule)
	}
	if r, _ := l.Fail(ctx, b, rule); !r.Allowed {
		t.Fatal("bloquear a una cuenta no debe afectar a otra")
	}
	var leaked int
	if err := db.Admin.QueryRow(ctx, `SELECT count(*) FROM rate_limits WHERE key LIKE '%ana%' OR key LIKE '%1.2.3.4%'`).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatalf("hay datos personales en las claves: %d %v", leaked, err)
	}
	if strings.Contains(a, "@") {
		t.Fatal("la clave contiene el correo")
	}
}

func TestConcurrentTakeIsExact(t *testing.T) {
	l, _, _ := newLimiter(t)
	key := l.Key("public", "slug")
	r := ratelimit.Rule{Max: 10, Window: time.Hour, Block: time.Hour}
	var allowed atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if res, err := l.Take(ctx, key, r); err == nil && res.Allowed {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	if allowed.Load() != int64(r.Max) {
		t.Fatalf("se permitieron %d intentos concurrentes (debían ser %d)", allowed.Load(), r.Max)
	}
}

func TestInvalidRuleIsRejected(t *testing.T) {
	l, _, _ := newLimiter(t)
	if _, err := l.Take(ctx, "k", ratelimit.Rule{}); err == nil {
		t.Fatal("aceptó una regla vacía")
	}
}

func TestFailsClosedWhenDatabaseIsDown(t *testing.T) {
	l, _, db := newLimiter(t)
	db.App.Close()
	if _, err := l.Fail(ctx, l.Key("login", "a"), rule); err == nil {
		t.Fatal("con la base de datos caída debe devolver error (el llamador deniega)")
	}
	if _, err := l.Blocked(ctx, l.Key("login", "a")); err == nil {
		t.Fatal("Blocked debe devolver error")
	}
}
