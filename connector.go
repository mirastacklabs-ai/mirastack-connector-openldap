// Package main implements the OpenLDAP identity-provider connector for
// MIRASTACK. It authenticates users against an OpenLDAP (or LDAP-compatible)
// directory service and integrates with the engine's AAAA framework via the
// IdentityProviderService gRPC contract.
//
// The connector implements three interfaces:
//   - mirastack.Plugin       — standard connector lifecycle
//   - mirastack.IdentityProviderAware — signals IDP capability to the engine
//   - connectorv1.IdentityProviderServiceServer — handles Authenticate + HealthCheck RPCs
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
	mirastack "github.com/mirastacklabs-ai/mirastack-connector-sdk-go"
	connectorv1 "github.com/mirastacklabs-ai/mirastack-connector-sdk-go/gen/connectorv1"
	"go.uber.org/zap"
)

// ldapConn is the subset of *ldap.Conn used by OpenLDAPConnector.
// Defined as an interface so tests can inject fakes without a live server.
type ldapConn interface {
	Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error)
	Bind(username, password string) error
	StartTLS(config *tls.Config) error
	SetTimeout(timeout time.Duration)
	Close() error
}

// OpenLDAPConfig holds the fully-resolved runtime configuration.
// Fields are populated from environment variables in main().
type OpenLDAPConfig struct {
	LDAPUrl         string        // e.g. "ldap://ldap.corp.local:389" or "ldaps://..."
	BindDN          string        // service-account DN for directory searches
	BindPassword    string        // service-account password
	BaseDN          string        // search base, e.g. "dc=corp,dc=local"
	UserFilter      string        // LDAP filter template, e.g. "(mail=%s)"
	EmailAttr       string        // attribute that holds the user's email
	DisplayNameAttr string        // attribute for display name
	UsernameAttr    string        // attribute for username (sAMAccountName for AD)
	RoleAttr        string        // optional — attribute for Mirastack role mapping
	DefaultRole     string        // role assigned when RoleAttr is empty or unmapped
	TLSSkipVerify   bool          // skip TLS certificate verification (dev only)
	Timeout         time.Duration // per-operation LDAP timeout
	ProviderName    string        // name used for registration, e.g. "openldap"
}

// OpenLDAPConnector is the MIRASTACK connector for OpenLDAP / LDAP directories.
// It implements mirastack.Plugin, mirastack.IdentityProviderAware, and
// connectorv1.IdentityProviderServiceServer directly on the same struct.
type OpenLDAPConnector struct {
	cfg     OpenLDAPConfig
	version string
	logger  *zap.Logger

	mu sync.RWMutex // protects cfg for runtime config updates

	// dialFn is the function used to open and bind a connection to the LDAP
	// server. When nil, the real ldap.DialURL path is taken. Tests inject a
	// fake implementation via newConnectorForTest to avoid requiring a live
	// LDAP server.
	dialFn func(cfg OpenLDAPConfig, logger *zap.Logger) (ldapConn, error)
}

// NewOpenLDAPConnector creates a connector with the given configuration.
// A probe-bind is performed at construction to surface misconfiguration early.
func NewOpenLDAPConnector(cfg OpenLDAPConfig, version string, logger *zap.Logger) (*OpenLDAPConnector, error) {
	c := &OpenLDAPConnector{
		cfg:     cfg,
		version: version,
		logger:  logger.Named("openldap"),
	}

	// Probe-bind to catch configuration problems before the engine calls
	// RegisterPlugin — this surfaces LDAP_URL / bind-credential errors at
	// startup rather than at the first authentication attempt.
	conn, err := c.dialAndBind()
	if err != nil {
		return nil, fmt.Errorf("openldap: initial bind failed (check LDAP_URL / LDAP_BIND_DN / LDAP_BIND_PASSWORD): %w", err)
	}
	conn.Close()

	return c, nil
}

// newConnectorForTest constructs a connector with the given dialFn without
// performing a probe-bind. Used exclusively in unit tests.
func newConnectorForTest(cfg OpenLDAPConfig, dialFn func(OpenLDAPConfig, *zap.Logger) (ldapConn, error), logger *zap.Logger) *OpenLDAPConnector {
	return &OpenLDAPConnector{
		cfg:    cfg,
		logger: logger,
		dialFn: dialFn,
	}
}

// ---------------------------------------------------------------------------
// mirastack.Plugin interface
// ---------------------------------------------------------------------------

// Info returns static plugin metadata. The Metadata map signals to the engine
// that this connector provides an IdentityProviderService.
func (c *OpenLDAPConnector) Info() *mirastack.PluginInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return &mirastack.PluginInfo{
		Name:        c.cfg.ProviderName,
		Version:     c.version,
		Description: "OpenLDAP identity-provider connector — authenticates users against an LDAP directory and integrates with the Mirastack AAAA framework.",
		Permissions: []mirastack.Permission{mirastack.PermissionRead},
		DevOpsStages: []mirastack.DevOpsStage{
			mirastack.StageOperate,
		},
		Metadata: map[string]string{
			"identity_provider":      "true",
			"identity_provider_type": "ldap",
		},
		ConfigParams: []mirastack.ConfigParam{
			{Key: "ldap_url", Type: "string", Required: true, Description: "LDAP server URL (ldap:// or ldaps://)"},
			{Key: "bind_dn", Type: "string", Required: true, Description: "Service-account DN for directory searches"},
			{Key: "bind_password", Type: "string", Required: true, IsSecret: true, Description: "Service-account password"},
			{Key: "base_dn", Type: "string", Required: true, Description: "LDAP search base DN"},
			{Key: "user_filter", Type: "string", Default: "(mail=%s)", Description: "LDAP filter template; %s is replaced with the user email"},
			{Key: "attr_email", Type: "string", Default: "mail", Description: "Attribute containing the user email"},
			{Key: "attr_display_name", Type: "string", Default: "displayName", Description: "Attribute for the user display name"},
			{Key: "attr_username", Type: "string", Default: "sAMAccountName", Description: "Attribute for the local username"},
			{Key: "attr_role", Type: "string", Description: "Optional attribute for Mirastack role mapping"},
			{Key: "default_role", Type: "string", Default: "operator", Description: "Role assigned when attr_role is absent or unmapped"},
			{Key: "tls_skip_verify", Type: "bool", Default: "false", Description: "Skip TLS certificate verification (development only)"},
			{Key: "timeout_seconds", Type: "int", Default: "10", Description: "Per-operation LDAP timeout in seconds"},
		},
	}
}

// Schema — connectors that act solely as identity providers have no Execute
// actions. We declare empty schemas to satisfy the Plugin interface.
func (c *OpenLDAPConnector) Schema() *mirastack.PluginSchema {
	return &mirastack.PluginSchema{}
}

// Execute — not applicable for a pure identity-provider connector.
func (c *OpenLDAPConnector) Execute(_ context.Context, req *mirastack.ExecuteRequest) (*mirastack.ExecuteResponse, error) {
	return nil, fmt.Errorf("openldap: connector %q has no executable actions", c.cfg.ProviderName)
}

// HealthCheck verifies that the connector can bind to the LDAP directory.
func (c *OpenLDAPConnector) HealthCheck(ctx context.Context) error {
	conn, err := c.dialAndBind()
	if err != nil {
		return fmt.Errorf("openldap: health check failed: %w", err)
	}
	conn.Close()
	return nil
}

// ConfigUpdated is called by the engine when runtime settings change. The
// connector rebuilds its configuration from the new values. Reconnection is
// lazy — the next authenticate call will use the updated settings.
func (c *OpenLDAPConnector) ConfigUpdated(_ context.Context, config map[string]string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if v := config["ldap_url"]; v != "" {
		c.cfg.LDAPUrl = v
	}
	if v := config["bind_dn"]; v != "" {
		c.cfg.BindDN = v
	}
	if v := config["bind_password"]; v != "" {
		c.cfg.BindPassword = v
	}
	if v := config["base_dn"]; v != "" {
		c.cfg.BaseDN = v
	}
	if v := config["user_filter"]; v != "" {
		c.cfg.UserFilter = v
	}
	if v := config["attr_email"]; v != "" {
		c.cfg.EmailAttr = v
	}
	if v := config["attr_display_name"]; v != "" {
		c.cfg.DisplayNameAttr = v
	}
	if v := config["attr_username"]; v != "" {
		c.cfg.UsernameAttr = v
	}
	if v := config["attr_role"]; v != "" {
		c.cfg.RoleAttr = v
	}
	if v := config["default_role"]; v != "" {
		c.cfg.DefaultRole = v
	}

	c.logger.Info("configuration updated")
	return nil
}

// ---------------------------------------------------------------------------
// mirastack.IdentityProviderAware interface
// ---------------------------------------------------------------------------

// AsIdentityProvider returns the connector itself as the
// IdentityProviderServiceServer implementation. The struct implements both
// Authenticate and HealthCheck gRPC methods directly.
func (c *OpenLDAPConnector) AsIdentityProvider() connectorv1.IdentityProviderServiceServer {
	return &openLDAPIdentityProviderServer{connector: c}
}

type openLDAPIdentityProviderServer struct {
	connector *OpenLDAPConnector
}

func (s *openLDAPIdentityProviderServer) Authenticate(ctx context.Context, req *connectorv1.AuthnRequest) (*connectorv1.AuthnResult, error) {
	return s.connector.Authenticate(ctx, req)
}

func (s *openLDAPIdentityProviderServer) HealthCheck(ctx context.Context, _ *connectorv1.HealthCheckRequest) (*connectorv1.HealthCheckResponse, error) {
	err := s.connector.HealthCheck(ctx)
	if err != nil {
		return &connectorv1.HealthCheckResponse{Healthy: false, Detail: err.Error()}, nil
	}
	return &connectorv1.HealthCheckResponse{Healthy: true, Detail: "OK"}, nil
}

// ---------------------------------------------------------------------------
// connectorv1.IdentityProviderServiceServer interface
// ---------------------------------------------------------------------------

// Authenticate validates user credentials against the LDAP directory using a
// three-step flow:
//  1. Bind as the service account to search the directory.
//  2. Search for the user entry whose email attribute matches req.Email.
//  3. Attempt a bind as the found user DN to verify their password.
//
// On success it returns an AuthnResult with user attributes populated. On
// failure it returns an AuthnResult with the appropriate reason code; errors
// are never propagated as gRPC errors (except for transient dial failures).
func (c *OpenLDAPConnector) Authenticate(_ context.Context, req *connectorv1.AuthnRequest) (*connectorv1.AuthnResult, error) {
	c.mu.RLock()
	cfg := c.cfg // snapshot under read-lock so we don't hold it during I/O
	c.mu.RUnlock()

	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" || req.Password == "" {
		return &connectorv1.AuthnResult{
			Reason:  connectorv1.AuthnReasonInvalidCredentials,
			Message: "email and password are required",
		}, nil
	}

	// Step 1 — bind as service account.
	conn, err := c.dialAndBind()
	if err != nil {
		c.logger.Warn("service-account bind failed",
			zap.String("email", email),
			zap.Error(err),
		)
		return &connectorv1.AuthnResult{
			Reason:  connectorv1.AuthnReasonProviderUnavailable,
			Message: fmt.Sprintf("LDAP directory unreachable: %s", err.Error()),
		}, nil
	}
	defer conn.Close()

	// Step 2 — search for the user entry.
	filter := fmt.Sprintf(cfg.UserFilter, ldap.EscapeFilter(email))
	attrs := []string{"dn", cfg.EmailAttr, cfg.DisplayNameAttr, cfg.UsernameAttr}
	if cfg.RoleAttr != "" {
		attrs = append(attrs, cfg.RoleAttr)
	}

	searchReq := ldap.NewSearchRequest(
		cfg.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1, // sizeLimit — we only want one entry
		int(cfg.Timeout.Seconds()),
		false,
		filter,
		attrs,
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		c.logger.Warn("LDAP search failed",
			zap.String("email", email),
			zap.String("filter", filter),
			zap.Error(err),
		)
		return &connectorv1.AuthnResult{
			Reason:  connectorv1.AuthnReasonProviderUnavailable,
			Message: fmt.Sprintf("LDAP search error: %s", err.Error()),
		}, nil
	}

	if len(result.Entries) == 0 {
		c.logger.Info("user not found in LDAP directory", zap.String("email", email))
		return &connectorv1.AuthnResult{
			Reason:  connectorv1.AuthnReasonUserNotFound,
			Message: "user not found in directory",
		}, nil
	}

	entry := result.Entries[0]
	userDN := entry.DN

	// Step 3 — bind as the found user to verify their password.
	if err := conn.Bind(userDN, req.Password); err != nil {
		c.logger.Info("user-bind failed (invalid credentials)",
			zap.String("email", email),
			zap.String("dn", userDN),
		)
		return &connectorv1.AuthnResult{
			Reason:  connectorv1.AuthnReasonInvalidCredentials,
			Message: "invalid credentials",
		}, nil
	}

	// Authentication succeeded — extract user attributes.
	userEmail := entry.GetAttributeValue(cfg.EmailAttr)
	if userEmail == "" {
		userEmail = email // fall back to the search key
	}
	displayName := entry.GetAttributeValue(cfg.DisplayNameAttr)
	username := entry.GetAttributeValue(cfg.UsernameAttr)
	if username == "" {
		// derive from email local-part
		if idx := strings.Index(userEmail, "@"); idx > 0 {
			username = userEmail[:idx]
		} else {
			username = userEmail
		}
	}

	// Map LDAP role attribute → Mirastack role.
	role := cfg.DefaultRole
	if cfg.RoleAttr != "" {
		if rawRole := entry.GetAttributeValue(cfg.RoleAttr); rawRole != "" {
			role = mapLDAPRole(rawRole, cfg.DefaultRole)
		}
	}

	c.logger.Info("LDAP authentication succeeded",
		zap.String("email", email),
		zap.String("dn", userDN),
		zap.String("role", role),
	)

	return &connectorv1.AuthnResult{
		User: &connectorv1.AuthnUser{
			// ExternalSubject is the stable LDAP DN — used for JIT
			// provisioning linkage in the engine so re-logins reuse
			// the same local User record even if email changes.
			ExternalSubject: userDN,
			Email:           userEmail,
			Username:        username,
			DisplayName:     displayName,
			Role:            role,
			ProviderName:    cfg.ProviderName,
			Status:          "active",
		},
		Reason: connectorv1.AuthnReasonOK,
	}, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// dialAndBind opens a new connection to the LDAP server and binds as the
// configured service account. The caller is responsible for calling Close on
// the returned ldapConn.
func (c *OpenLDAPConnector) dialAndBind() (ldapConn, error) {
	c.mu.RLock()
	cfg := c.cfg
	fn := c.dialFn
	c.mu.RUnlock()

	if fn != nil {
		conn, err := fn(cfg, c.logger)
		if err != nil {
			return nil, err
		}
		if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("bind as %s: %w", cfg.BindDN, err)
		}
		return conn, nil
	}
	return realDialAndBind(cfg, c.logger)
}

// realDialAndBind performs the actual LDAP dial and service-account bind.
func realDialAndBind(cfg OpenLDAPConfig, logger *zap.Logger) (ldapConn, error) {
	var conn *ldap.Conn
	var err error

	if strings.HasPrefix(cfg.LDAPUrl, "ldaps://") {
		conn, err = ldap.DialURL(
			cfg.LDAPUrl,
			ldap.DialWithDialer(&net.Dialer{Timeout: cfg.Timeout}),
			ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: cfg.TLSSkipVerify}), //nolint:gosec
		)
	} else {
		conn, err = ldap.DialURL(cfg.LDAPUrl, ldap.DialWithDialer(&net.Dialer{Timeout: cfg.Timeout}))
	}
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", cfg.LDAPUrl, err)
	}

	// Set a per-operation deadline.
	conn.SetTimeout(cfg.Timeout)

	// Optionally upgrade a plain LDAP connection to TLS via StartTLS.
	if strings.HasPrefix(cfg.LDAPUrl, "ldap://") && !cfg.TLSSkipVerify {
		if err := conn.StartTLS(&tls.Config{ServerName: ldapHost(cfg.LDAPUrl)}); err != nil {
			// StartTLS failure is non-fatal — many internal LDAP deployments
			// operate without it. Log and continue over plaintext.
			logger.Warn("StartTLS failed, continuing over plaintext", zap.Error(err))
		}
	}

	if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
		conn.Close()
		return nil, fmt.Errorf("bind as %s: %w", cfg.BindDN, err)
	}
	return conn, nil
}

// ldapHost extracts the hostname from an ldap:// URL for use in StartTLS.
func ldapHost(url string) string {
	host := strings.TrimPrefix(url, "ldap://")
	if idx := strings.LastIndex(host, ":"); idx >= 0 {
		host = host[:idx]
	}
	return host
}

// mapLDAPRole maps an LDAP attribute value to a Mirastack role string. The
// connector convention is simple: if the attribute value is already one of the
// three canonical roles it is used directly; otherwise the defaultRole is
// returned. Operators can extend this by subclassing or wrapping the connector.
func mapLDAPRole(ldapValue, defaultRole string) string {
	switch strings.ToLower(ldapValue) {
	case "operator", "mirastack-operator":
		return "operator"
	case "engineer", "mirastack-engineer":
		return "engineer"
	case "admin", "mirastack-admin", "administrator":
		return "admin"
	default:
		return defaultRole
	}
}
