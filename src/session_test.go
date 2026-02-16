package src

import (
	"sync"
	"testing"
	"time"

	"github.com/sevensolutions/traefik-oidc-auth/src/logging"
	"github.com/sevensolutions/traefik-oidc-auth/src/session"
)

func TestSessionIdpTokenExpiration(t *testing.T) {
	config := &Config{
		Provider: &ProviderConfig{
			TokenRenewalThreshold: 0.5,
		},
		SessionCookie: &SessionCookieConfig{
			MaxAge: 0,
		},
	}

	logger := logging.CreateLogger(logging.LevelDebug)

	toa := &TraefikOidcAuth{
		logger: logger,
		Config: config,
	}

	now := time.Now()

	sessionState := &session.SessionState{
		RefreshedAt:    now.Add(-29 * time.Second),
		TokenExpiresIn: 60,
	}

	expiresSoon := checkIdpTokenExpiresSoon(toa, sessionState)

	if expiresSoon {
		t.Fail()
	}

	sessionState = &session.SessionState{
		RefreshedAt:    now.Add(-30 * time.Second),
		TokenExpiresIn: 60,
	}

	expiresSoon = checkIdpTokenExpiresSoon(toa, sessionState)

	if !expiresSoon {
		t.Fail()
	}
}

func TestConcurrentSessionLock(t *testing.T) {
	toa := &TraefikOidcAuth{}

	sessionId := "test-session-id"

	var wg sync.WaitGroup
	counter := 0
	iterations := 100

	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lock := toa.getSessionLock(sessionId)
			lock.Lock()
			counter++
			lock.Unlock()
		}()
	}

	wg.Wait()

	if counter != iterations {
		t.Errorf("Expected counter to be %d, got %d", iterations, counter)
	}
}

func TestPerSessionLocksAreIndependent(t *testing.T) {
	toa := &TraefikOidcAuth{}

	lock1 := toa.getSessionLock("session-1")
	lock2 := toa.getSessionLock("session-2")

	if lock1 == lock2 {
		t.Error("Different sessions should have different locks")
	}

	lock1Again := toa.getSessionLock("session-1")
	if lock1 != lock1Again {
		t.Error("Same session ID should return the same lock")
	}
}
