package src

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/sevensolutions/traefik-oidc-auth/src/config"
	"github.com/sevensolutions/traefik-oidc-auth/src/logging"
	"github.com/sevensolutions/traefik-oidc-auth/src/oidc"
	"github.com/sevensolutions/traefik-oidc-auth/src/session"
)

func TestSessionIdpTokenExpiration(t *testing.T) {
	config := &config.Config{
		Provider: &config.ProviderConfig{
			TokenRenewalThreshold: 0.5,
		},
		SessionCookie: &config.SessionCookieConfig{
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

func TestValidateSessionTicketUsesRecentlyRenewedSession(t *testing.T) {
	cfg := CreateConfig()
	cfg.Secret = config.DefaultSecret
	cfg.Provider.ClientId = "test-client"
	cfg.Provider.ClientSecret = "test-secret"
	cfg.Provider.TokenValidation = "Introspection"
	cfg.Provider.TokenRenewalThreshold = 0.5

	logger := logging.CreateLogger(logging.LevelDebug)

	var stateLock sync.Mutex
	activeTokens := map[string]bool{
		"access-1": true,
	}
	refreshCalls := 0
	firstRefreshStarted := make(chan struct{})
	allowFirstRefresh := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/introspect":
			if err := req.ParseForm(); err != nil {
				t.Errorf("failed to parse introspection request: %v", err)
				http.Error(rw, err.Error(), http.StatusBadRequest)
				return
			}

			stateLock.Lock()
			active := activeTokens[req.Form.Get("token")]
			stateLock.Unlock()

			rw.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(rw).Encode(map[string]interface{}{"active": active, "sub": "alice"}); err != nil {
				t.Errorf("failed to encode introspection response: %v", err)
			}
		case "/token":
			if err := req.ParseForm(); err != nil {
				t.Errorf("failed to parse token request: %v", err)
				http.Error(rw, err.Error(), http.StatusBadRequest)
				return
			}

			stateLock.Lock()
			refreshCalls++
			callNumber := refreshCalls
			stateLock.Unlock()

			if callNumber == 1 {
				if req.Form.Get("refresh_token") != "refresh-1" {
					t.Errorf("expected first refresh token to be refresh-1, got %s", req.Form.Get("refresh_token"))
					http.Error(rw, "unexpected refresh token", http.StatusBadRequest)
					return
				}

				close(firstRefreshStarted)
				<-allowFirstRefresh

				stateLock.Lock()
				activeTokens["access-2"] = true
				stateLock.Unlock()

				rw.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(rw).Encode(oidc.OidcTokenResponse{
					AccessToken:  "access-2",
					IdToken:      "id-2",
					RefreshToken: "refresh-2",
					ExpiresIn:    120,
				}); err != nil {
					t.Errorf("failed to encode token response: %v", err)
				}
				return
			}

			http.Error(rw, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		default:
			t.Errorf("unexpected request path %s", req.URL.Path)
			http.NotFound(rw, req)
		}
	}))
	defer server.Close()

	toa := &TraefikOidcAuth{
		logger:         logger,
		httpClient:     server.Client(),
		Config:         cfg,
		SessionStorage: session.CreateCookieSessionStorage(),
		DiscoveryDocument: &oidc.OidcDiscovery{
			TokenEndpoint:         server.URL + "/token",
			IntrospectionEndpoint: server.URL + "/introspect",
		},
	}

	staleSession := &session.SessionState{
		Id:             "session-1",
		RefreshedAt:    time.Now().Add(-80 * time.Second),
		AccessToken:    "access-1",
		IdToken:        "id-1",
		RefreshToken:   "refresh-1",
		TokenExpiresIn: 100,
	}

	sessionTicket, err := toa.SessionStorage.StoreSession(toa.logger, toa.Config, staleSession.Id, staleSession)
	if err != nil {
		t.Fatalf("failed to store session: %v", err)
	}

	type validationResult struct {
		session        *session.SessionState
		claims         map[string]interface{}
		updatedSession *session.SessionState
		err            error
	}

	firstResultCh := make(chan validationResult, 1)
	secondResultCh := make(chan validationResult, 1)

	go func() {
		sessionState, claims, updatedSession, err := validateSessionTicket(toa, sessionTicket)
		firstResultCh <- validationResult{session: sessionState, claims: claims, updatedSession: updatedSession, err: err}
	}()

	<-firstRefreshStarted

	go func() {
		sessionState, claims, updatedSession, err := validateSessionTicket(toa, sessionTicket)
		secondResultCh <- validationResult{session: sessionState, claims: claims, updatedSession: updatedSession, err: err}
	}()

	close(allowFirstRefresh)

	firstResult := <-firstResultCh
	secondResult := <-secondResultCh

	if firstResult.err != nil {
		t.Fatalf("first request failed: %v", firstResult.err)
	}
	if secondResult.err != nil {
		t.Fatalf("second request failed: %v", secondResult.err)
	}
	if firstResult.session == nil || secondResult.session == nil {
		t.Fatal("expected both requests to return a session")
	}
	if firstResult.session.AccessToken != "access-2" {
		t.Fatalf("expected first request to use renewed access token, got %s", firstResult.session.AccessToken)
	}
	if secondResult.session.AccessToken != "access-2" {
		t.Fatalf("expected second request to reuse renewed access token, got %s", secondResult.session.AccessToken)
	}
	if secondResult.updatedSession == nil {
		t.Fatal("expected second request to return an updated session for cookie refresh")
	}
	if secondResult.claims["sub"] != "alice" {
		t.Fatalf("expected remembered session claims to be reused, got %+v", secondResult.claims)
	}

	stateLock.Lock()
	defer stateLock.Unlock()
	if refreshCalls != 1 {
		t.Fatalf("expected exactly one refresh attempt, got %d", refreshCalls)
	}
}
