// Package main is the entry-point for the mirastack-connector-openldap process.
// It reads runtime configuration from environment variables, constructs the
// OpenLDAP connector, and calls mirastack.Serve() to start the gRPC server and
// register with the Mirastack Engine.
package main

import (
	"log"
	"os"
	"strconv"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	mirastack "github.com/mirastacklabs-ai/mirastack-connector-sdk-go"
)

func main() {
	// ── Logging ──────────────────────────────────────────────────────────────
	logLevel := zapcore.InfoLevel
	if v := os.Getenv("LOG_LEVEL"); v != "" {
		if err := logLevel.UnmarshalText([]byte(v)); err != nil {
			log.Printf("invalid LOG_LEVEL %q, defaulting to info", v)
		}
	}
	zapCfg := zap.NewProductionConfig()
	zapCfg.Level = zap.NewAtomicLevelAt(logLevel)
	logger, err := zapCfg.Build()
	if err != nil {
		log.Fatalf("failed to build logger: %v", err)
	}
	defer func() { _ = logger.Sync() }()

	// ── Config from environment ───────────────────────────────────────────────
	// Required
	ldapURL := mustEnv("LDAP_URL", "ldap://localhost:389", logger)
	bindDN := mustEnv("LDAP_BIND_DN", "", logger)
	bindPassword := mustEnv("LDAP_BIND_PASSWORD", "", logger)
	baseDN := mustEnv("LDAP_BASE_DN", "", logger)

	// Optional — sensible defaults.
	userFilter := envOrDefault("LDAP_USER_FILTER", "(mail=%s)")
	emailAttr := envOrDefault("LDAP_ATTR_EMAIL", "mail")
	displayNameAttr := envOrDefault("LDAP_ATTR_DISPLAY_NAME", "displayName")
	usernameAttr := envOrDefault("LDAP_ATTR_USERNAME", "sAMAccountName")
	roleAttr := envOrDefault("LDAP_ATTR_ROLE", "") // empty → use defaultRole
	defaultRole := envOrDefault("LDAP_DEFAULT_ROLE", "operator")

	tlsSkipVerify := envBool("LDAP_TLS_SKIP_VERIFY", false)
	timeoutSec := envInt("LDAP_TIMEOUT_SECONDS", 10)

	providerName := envOrDefault("MIRASTACK_PROVIDER_NAME", "openldap")
	// These env vars are read by mirastack.Serve() internally; capture them
	// here only for the startup log message.
	engineAddr := envOrDefault("MIRASTACK_ENGINE_ADDR", "")
	grpcAddr := envOrDefault("MIRASTACK_GRPC_ADDR", "")
	pluginVersion := envOrDefault("MIRASTACK_PLUGIN_VERSION", "1.0.0")

	cfg := OpenLDAPConfig{
		LDAPUrl:         ldapURL,
		BindDN:          bindDN,
		BindPassword:    bindPassword,
		BaseDN:          baseDN,
		UserFilter:      userFilter,
		EmailAttr:       emailAttr,
		DisplayNameAttr: displayNameAttr,
		UsernameAttr:    usernameAttr,
		RoleAttr:        roleAttr,
		DefaultRole:     defaultRole,
		TLSSkipVerify:   tlsSkipVerify,
		Timeout:         time.Duration(timeoutSec) * time.Second,
		ProviderName:    providerName,
	}

	connector, err := NewOpenLDAPConnector(cfg, pluginVersion, logger)
	if err != nil {
		logger.Fatal("failed to initialise OpenLDAP connector", zap.Error(err))
	}

	logger.Info("starting mirastack-connector-openldap",
		zap.String("provider_name", providerName),
		zap.String("ldap_url", ldapURL),
		zap.String("engine_addr", engineAddr),
		zap.String("grpc_addr", grpcAddr),
	)

	// Set the standard environment variables that Serve() reads internally.
	// mirastack.Serve() reads MIRASTACK_ENGINE_ADDR and MIRASTACK_GRPC_ADDR
	// directly from the environment — no ServeOptions struct is needed.
	mirastack.Serve(connector)
}

// ── helpers ──────────────────────────────────────────────────────────────────

// mustEnv returns the environment variable value or, when no default is
// provided (""), logs a fatal error and exits.
func mustEnv(key, defaultValue string, logger *zap.Logger) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	if defaultValue != "" {
		return defaultValue
	}
	logger.Fatal("required environment variable is not set", zap.String("var", key))
	return "" // unreachable — satisfies the compiler
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}
