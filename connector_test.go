package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	connectorv1 "github.com/mirastacklabs-ai/mirastack-connector-sdk-go/gen/connectorv1"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

// ---------------------------------------------------------------------------
// fakeLDAPConn — test double for the ldapConn interface
// ---------------------------------------------------------------------------

// fakeLDAPConn is a programmable fake implementation of ldapConn. Each test
// configures exactly which calls should succeed or fail.
type fakeLDAPConn struct {
	// searchEntries is returned by Search on success.
	searchEntries []*ldap.Entry
	// searchErr, if non-nil, is returned by Search instead of searchEntries.
	searchErr error
	// bindCalls records every Bind(dn, pw) call for assertion.
	bindCalls []bindCall
	// bindErrs is a queue of errors to return from successive Bind calls.
	// When the queue is exhausted, nil is returned.
	bindErrs []error
	// closed records whether Close was called.
	closed bool
}

type bindCall struct {
	DN       string
	Password string
}

func (f *fakeLDAPConn) Search(_ *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if f.searchErr != nil {
		return nil, f.searchErr
	}
	return &ldap.SearchResult{Entries: f.searchEntries}, nil
}

func (f *fakeLDAPConn) Bind(dn, password string) error {
	f.bindCalls = append(f.bindCalls, bindCall{DN: dn, Password: password})
	if len(f.bindErrs) > 0 {
		err := f.bindErrs[0]
		f.bindErrs = f.bindErrs[1:]
		return err
	}
	return nil
}

func (f *fakeLDAPConn) StartTLS(_ *tls.Config) error { return nil }

func (f *fakeLDAPConn) SetTimeout(_ time.Duration) {}

func (f *fakeLDAPConn) Close() error {
	f.closed = true
	return nil
}

// Compile-time assertion that *fakeLDAPConn satisfies ldapConn.
var _ ldapConn = (*fakeLDAPConn)(nil)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// fakeDialFn returns a factory that always succeeds and provides the given
// *fakeLDAPConn (service-account bind included).
func fakeDialFn(conn *fakeLDAPConn) func(OpenLDAPConfig, *zap.Logger) (ldapConn, error) {
	return func(_ OpenLDAPConfig, _ *zap.Logger) (ldapConn, error) {
		return conn, nil
	}
}

// unreachableDialFn returns a factory that always fails with a dial error.
func unreachableDialFn() func(OpenLDAPConfig, *zap.Logger) (ldapConn, error) {
	return func(cfg OpenLDAPConfig, _ *zap.Logger) (ldapConn, error) {
		return nil, fmt.Errorf("dial %s: connection refused", cfg.LDAPUrl)
	}
}

// buildEntry is a helper to construct a minimal *ldap.Entry for tests.
func buildEntry(dn string, attrs map[string][]string) *ldap.Entry {
	e := ldap.NewEntry(dn, attrs)
	return e
}

// defaultCfg returns an OpenLDAPConfig suitable for unit tests.
func defaultCfg() OpenLDAPConfig {
	return OpenLDAPConfig{
		LDAPUrl:         "ldap://localhost:389",
		BindDN:          "cn=admin,dc=example,dc=com",
		BindPassword:    "admin",
		BaseDN:          "dc=example,dc=com",
		UserFilter:      "(mail=%s)",
		EmailAttr:       "mail",
		DisplayNameAttr: "displayName",
		UsernameAttr:    "uid",
		DefaultRole:     "operator",
		TLSSkipVerify:   true, // prevent StartTLS in tests
		Timeout:         5 * time.Second,
		ProviderName:    "test-ldap",
	}
}

// ---------------------------------------------------------------------------
// Authenticate — success path
// ---------------------------------------------------------------------------

func TestAuthenticate_Success(t *testing.T) {
	logger := zaptest.NewLogger(t)
	conn := &fakeLDAPConn{
		searchEntries: []*ldap.Entry{
			buildEntry("uid=alice,dc=example,dc=com", map[string][]string{
				"mail":        {"alice@example.com"},
				"displayName": {"Alice Smith"},
				"uid":         {"alice"},
			}),
		},
	}

	c := newConnectorForTest(defaultCfg(), fakeDialFn(conn), logger)

	result, err := c.Authenticate(context.Background(), &connectorv1.AuthnRequest{
		Email:    "alice@example.com",
		Password: "secret",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Reason != connectorv1.AuthnReasonOK {
		t.Fatalf("expected OK reason, got %q (msg: %s)", result.Reason, result.Message)
	}
	if result.User == nil {
		t.Fatal("expected User to be set on success")
	}
	if result.User.Email != "alice@example.com" {
		t.Errorf("Email: got %q, want %q", result.User.Email, "alice@example.com")
	}
	if result.User.Username != "alice" {
		t.Errorf("Username: got %q, want %q", result.User.Username, "alice")
	}
	if result.User.DisplayName != "Alice Smith" {
		t.Errorf("DisplayName: got %q, want %q", result.User.DisplayName, "Alice Smith")
	}
	if result.User.ExternalSubject != "uid=alice,dc=example,dc=com" {
		t.Errorf("ExternalSubject: got %q, want DN", result.User.ExternalSubject)
	}
	if result.User.Role != "operator" {
		t.Errorf("Role: got %q, want %q", result.User.Role, "operator")
	}

	// Two Bind calls: (1) service-account bind, (2) user-DN bind.
	if len(conn.bindCalls) != 2 {
		t.Fatalf("expected 2 Bind calls, got %d", len(conn.bindCalls))
	}
	if conn.bindCalls[0].DN != "cn=admin,dc=example,dc=com" {
		t.Errorf("first bind DN: got %q", conn.bindCalls[0].DN)
	}
	if conn.bindCalls[1].DN != "uid=alice,dc=example,dc=com" {
		t.Errorf("second bind DN: got %q", conn.bindCalls[1].DN)
	}
	if conn.bindCalls[1].Password != "secret" {
		t.Errorf("user-bind password: got %q", conn.bindCalls[1].Password)
	}
}

// ---------------------------------------------------------------------------
// Authenticate — empty email/password
// ---------------------------------------------------------------------------

func TestAuthenticate_EmptyCredentials(t *testing.T) {
	logger := zaptest.NewLogger(t)
	conn := &fakeLDAPConn{}
	c := newConnectorForTest(defaultCfg(), fakeDialFn(conn), logger)

	cases := []struct {
		name     string
		email    string
		password string
	}{
		{"empty email", "", "secret"},
		{"empty password", "alice@example.com", ""},
		{"both empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := c.Authenticate(context.Background(), &connectorv1.AuthnRequest{
				Email:    tc.email,
				Password: tc.password,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Reason != connectorv1.AuthnReasonInvalidCredentials {
				t.Errorf("expected InvalidCredentials, got %q", result.Reason)
			}
			// Empty credentials must not trigger a dial.
			if len(conn.bindCalls) != 0 {
				t.Errorf("expected no Bind calls for empty credentials")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Authenticate — user not found
// ---------------------------------------------------------------------------

func TestAuthenticate_UserNotFound(t *testing.T) {
	logger := zaptest.NewLogger(t)
	conn := &fakeLDAPConn{
		searchEntries: []*ldap.Entry{}, // empty result
	}
	c := newConnectorForTest(defaultCfg(), fakeDialFn(conn), logger)

	result, err := c.Authenticate(context.Background(), &connectorv1.AuthnRequest{
		Email:    "nobody@example.com",
		Password: "secret",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Reason != connectorv1.AuthnReasonUserNotFound {
		t.Errorf("expected UserNotFound, got %q", result.Reason)
	}
	if result.User != nil {
		t.Errorf("expected nil User on failure")
	}
}

// ---------------------------------------------------------------------------
// Authenticate — wrong password (user-bind fails)
// ---------------------------------------------------------------------------

func TestAuthenticate_InvalidPassword(t *testing.T) {
	logger := zaptest.NewLogger(t)
	conn := &fakeLDAPConn{
		searchEntries: []*ldap.Entry{
			buildEntry("uid=alice,dc=example,dc=com", map[string][]string{
				"mail": {"alice@example.com"},
				"uid":  {"alice"},
			}),
		},
		// First Bind (service-account) succeeds via default (no error).
		// Second Bind (user) fails.
		bindErrs: []error{nil, errors.New("ldap: invalid credentials")},
	}
	c := newConnectorForTest(defaultCfg(), fakeDialFn(conn), logger)

	result, err := c.Authenticate(context.Background(), &connectorv1.AuthnRequest{
		Email:    "alice@example.com",
		Password: "wrongpassword",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Reason != connectorv1.AuthnReasonInvalidCredentials {
		t.Errorf("expected InvalidCredentials, got %q", result.Reason)
	}
}

// ---------------------------------------------------------------------------
// Authenticate — LDAP server unreachable
// ---------------------------------------------------------------------------

func TestAuthenticate_ProviderUnavailable(t *testing.T) {
	logger := zaptest.NewLogger(t)
	c := newConnectorForTest(defaultCfg(), unreachableDialFn(), logger)

	result, err := c.Authenticate(context.Background(), &connectorv1.AuthnRequest{
		Email:    "alice@example.com",
		Password: "secret",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Reason != connectorv1.AuthnReasonProviderUnavailable {
		t.Errorf("expected ProviderUnavailable, got %q", result.Reason)
	}
}

// ---------------------------------------------------------------------------
// Authenticate — LDAP search error
// ---------------------------------------------------------------------------

func TestAuthenticate_SearchError(t *testing.T) {
	logger := zaptest.NewLogger(t)
	conn := &fakeLDAPConn{
		searchErr: errors.New("ldap: server-side error 32"),
	}
	c := newConnectorForTest(defaultCfg(), fakeDialFn(conn), logger)

	result, err := c.Authenticate(context.Background(), &connectorv1.AuthnRequest{
		Email:    "alice@example.com",
		Password: "secret",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Reason != connectorv1.AuthnReasonProviderUnavailable {
		t.Errorf("expected ProviderUnavailable on search error, got %q", result.Reason)
	}
}

// ---------------------------------------------------------------------------
// HealthCheck — healthy
// ---------------------------------------------------------------------------

func TestHealthCheck_Healthy(t *testing.T) {
	logger := zaptest.NewLogger(t)
	conn := &fakeLDAPConn{}
	c := newConnectorForTest(defaultCfg(), fakeDialFn(conn), logger)

	resp, err := c.AsIdentityProvider().HealthCheck(context.Background(), &connectorv1.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Healthy {
		t.Errorf("expected Healthy=true, got false (detail: %s)", resp.Detail)
	}
}

// ---------------------------------------------------------------------------
// HealthCheck — unreachable
// ---------------------------------------------------------------------------

func TestHealthCheck_Unreachable(t *testing.T) {
	logger := zaptest.NewLogger(t)
	c := newConnectorForTest(defaultCfg(), unreachableDialFn(), logger)

	resp, err := c.AsIdentityProvider().HealthCheck(context.Background(), &connectorv1.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("HealthCheck must not return a gRPC error: %v", err)
	}
	if resp.Healthy {
		t.Error("expected Healthy=false when server is unreachable")
	}
	if resp.Detail == "" {
		t.Error("expected non-empty Detail on failure")
	}
}

// ---------------------------------------------------------------------------
// ConfigUpdated — changes are applied to next Authenticate
// ---------------------------------------------------------------------------

func TestConfigUpdated_AppliesChanges(t *testing.T) {
	logger := zaptest.NewLogger(t)
	conn := &fakeLDAPConn{
		searchEntries: []*ldap.Entry{
			buildEntry("uid=bob,dc=newdomain,dc=com", map[string][]string{
				"email": {"bob@newdomain.com"},
				"cn":    {"Bob Builder"},
				"uid":   {"bob"},
			}),
		},
	}
	c := newConnectorForTest(defaultCfg(), fakeDialFn(conn), logger)

	// Update to a new base DN and email attribute.
	err := c.ConfigUpdated(context.Background(), map[string]string{
		"base_dn":    "dc=newdomain,dc=com",
		"attr_email": "email",
	})
	if err != nil {
		t.Fatalf("ConfigUpdated returned error: %v", err)
	}

	c.mu.RLock()
	gotBaseDN := c.cfg.BaseDN
	gotEmailAttr := c.cfg.EmailAttr
	c.mu.RUnlock()

	if gotBaseDN != "dc=newdomain,dc=com" {
		t.Errorf("BaseDN not updated: got %q", gotBaseDN)
	}
	if gotEmailAttr != "email" {
		t.Errorf("EmailAttr not updated: got %q", gotEmailAttr)
	}
}

// ---------------------------------------------------------------------------
// Role mapping
// ---------------------------------------------------------------------------

func TestAuthenticate_RoleMappingFromAttribute(t *testing.T) {
	cases := []struct {
		name         string
		ldapRoleVal  string
		expectedRole string
		defaultRole  string
	}{
		{"operator keyword", "operator", "operator", "operator"},
		{"mirastack-operator prefix", "mirastack-operator", "operator", "operator"},
		{"engineer keyword", "engineer", "engineer", "operator"},
		{"mirastack-engineer prefix", "mirastack-engineer", "engineer", "operator"},
		{"admin keyword", "admin", "admin", "operator"},
		{"administrator synonym", "administrator", "admin", "operator"},
		{"mirastack-admin prefix", "mirastack-admin", "admin", "operator"},
		{"unmapped falls back to default", "some-other-group", "engineer", "engineer"},
		{"case insensitive", "ENGINEER", "engineer", "operator"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logger := zaptest.NewLogger(t)
			conn := &fakeLDAPConn{
				searchEntries: []*ldap.Entry{
					buildEntry("uid=user,dc=example,dc=com", map[string][]string{
						"mail":     {"user@example.com"},
						"uid":      {"user"},
						"mirarole": {tc.ldapRoleVal},
					}),
				},
			}

			cfg := defaultCfg()
			cfg.RoleAttr = "mirarole"
			cfg.DefaultRole = tc.defaultRole

			c := newConnectorForTest(cfg, fakeDialFn(conn), logger)
			result, err := c.Authenticate(context.Background(), &connectorv1.AuthnRequest{
				Email:    "user@example.com",
				Password: "secret",
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Reason != connectorv1.AuthnReasonOK {
				t.Fatalf("expected OK, got %q", result.Reason)
			}
			if result.User.Role != tc.expectedRole {
				t.Errorf("role: got %q, want %q", result.User.Role, tc.expectedRole)
			}
		})
	}
}

func TestAuthenticate_RoleAttributeAbsent_UsesDefault(t *testing.T) {
	logger := zaptest.NewLogger(t)
	conn := &fakeLDAPConn{
		searchEntries: []*ldap.Entry{
			buildEntry("uid=user,dc=example,dc=com", map[string][]string{
				"mail": {"user@example.com"},
				"uid":  {"user"},
				// mirarole attribute NOT present
			}),
		},
	}

	cfg := defaultCfg()
	cfg.RoleAttr = "mirarole"
	cfg.DefaultRole = "engineer"

	c := newConnectorForTest(cfg, fakeDialFn(conn), logger)
	result, err := c.Authenticate(context.Background(), &connectorv1.AuthnRequest{
		Email:    "user@example.com",
		Password: "secret",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.User.Role != "engineer" {
		t.Errorf("expected DefaultRole %q when attribute absent, got %q", "engineer", result.User.Role)
	}
}

// ---------------------------------------------------------------------------
// Username derivation fallback
// ---------------------------------------------------------------------------

func TestAuthenticate_UsernameFromEmailWhenAttrMissing(t *testing.T) {
	logger := zaptest.NewLogger(t)
	conn := &fakeLDAPConn{
		searchEntries: []*ldap.Entry{
			buildEntry("uid=carol,dc=example,dc=com", map[string][]string{
				"mail": {"carol@example.com"},
				// uid attribute not returned
			}),
		},
	}

	c := newConnectorForTest(defaultCfg(), fakeDialFn(conn), logger)
	result, err := c.Authenticate(context.Background(), &connectorv1.AuthnRequest{
		Email:    "carol@example.com",
		Password: "secret",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should derive "carol" from "carol@example.com"
	if result.User.Username != "carol" {
		t.Errorf("expected derived username %q, got %q", "carol", result.User.Username)
	}
}

// ---------------------------------------------------------------------------
// mapLDAPRole unit tests (pure function)
// ---------------------------------------------------------------------------

func TestMapLDAPRole(t *testing.T) {
	cases := []struct {
		input    string
		def      string
		expected string
	}{
		{"operator", "operator", "operator"},
		{"OPERATOR", "operator", "operator"},
		{"mirastack-operator", "operator", "operator"},
		{"engineer", "operator", "engineer"},
		{"mirastack-engineer", "operator", "engineer"},
		{"admin", "operator", "admin"},
		{"administrator", "operator", "admin"},
		{"mirastack-admin", "operator", "admin"},
		{"", "engineer", "engineer"},
		{"unknown-group", "admin", "admin"},
	}
	for _, tc := range cases {
		got := mapLDAPRole(tc.input, tc.def)
		if got != tc.expected {
			t.Errorf("mapLDAPRole(%q, %q) = %q; want %q", tc.input, tc.def, got, tc.expected)
		}
	}
}

// ---------------------------------------------------------------------------
// ldapHost unit tests (pure function)
// ---------------------------------------------------------------------------

func TestLdapHost(t *testing.T) {
	cases := []struct {
		url      string
		expected string
	}{
		{"ldap://ldap.corp.local:389", "ldap.corp.local"},
		{"ldap://ldap.corp.local", "ldap.corp.local"},
		{"ldap://192.168.1.10:389", "192.168.1.10"},
	}
	for _, tc := range cases {
		got := ldapHost(tc.url)
		if got != tc.expected {
			t.Errorf("ldapHost(%q) = %q; want %q", tc.url, got, tc.expected)
		}
	}
}

// ---------------------------------------------------------------------------
// Info and Schema — static sanity checks
// ---------------------------------------------------------------------------

func TestInfo_ContainsIdentityProviderMetadata(t *testing.T) {
	logger := zaptest.NewLogger(t)
	c := newConnectorForTest(defaultCfg(), fakeDialFn(&fakeLDAPConn{}), logger)

	info := c.Info()
	if info == nil {
		t.Fatal("Info() must not return nil")
	}
	if info.Metadata["identity_provider"] != "true" {
		t.Errorf("expected Metadata[identity_provider]=true, got %q", info.Metadata["identity_provider"])
	}
	if info.Metadata["identity_provider_type"] != "ldap" {
		t.Errorf("expected Metadata[identity_provider_type]=ldap, got %q", info.Metadata["identity_provider_type"])
	}
}

func TestSchema_IsEmpty(t *testing.T) {
	logger := zaptest.NewLogger(t)
	c := newConnectorForTest(defaultCfg(), fakeDialFn(&fakeLDAPConn{}), logger)
	if c.Schema() == nil {
		t.Fatal("Schema() must not return nil")
	}
}

func TestAsIdentityProvider_ReturnsServer(t *testing.T) {
	logger := zaptest.NewLogger(t)
	c := newConnectorForTest(defaultCfg(), fakeDialFn(&fakeLDAPConn{}), logger)
	if c.AsIdentityProvider() == nil {
		t.Error("AsIdentityProvider() must not return nil")
	}
}
