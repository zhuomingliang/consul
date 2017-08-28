package config

import (
	"fmt"
	"net"
	"reflect"
	"strconv"
	"time"

	"github.com/hashicorp/consul/agent/structs"
	"github.com/hashicorp/consul/types"
)

// RuntimeConfig specifies the configuration the consul agent actually
// uses. Is is derived from one or more Config structures which can come
// from files, flags and/or environment variables.
type RuntimeConfig struct {
	// simple values

	ACLAgentMasterToken string
	ACLAgentToken       string
	ACLDatacenter       string
	ACLDefaultPolicy    string
	ACLDisabledTTL      time.Duration // todo(fs): configure me!
	ACLDownPolicy       string
	ACLEnforceVersion8  bool
	ACLMasterToken      string
	ACLReplicationToken string
	ACLTTL              time.Duration
	ACLToken            string

	AutopilotCleanupDeadServers      bool
	AutopilotDisableUpgradeMigration bool
	AutopilotLastContactThreshold    time.Duration
	AutopilotMaxTrailingLogs         uint64
	AutopilotRedundancyZoneTag       string
	AutopilotServerStabilizationTime time.Duration
	AutopilotUpgradeVersionTag       string

	DNSAllowStale         bool
	DNSDisableCompression bool
	DNSDomain             string
	DNSEnableTruncate     bool
	DNSMaxStale           time.Duration
	DNSNodeTTL            time.Duration
	DNSOnlyPassing        bool
	DNSRecursorTimeout    time.Duration
	DNSServiceTTL         map[string]time.Duration
	DNSUDPAnswerLimit     int
	DNSRecursors          []string

	Bootstrap           bool
	BootstrapExpect     int
	CAFile              string
	CAPath              string
	CertFile            string
	CheckUpdateInterval time.Duration
	Checks              []*structs.CheckDefinition
	Datacenter          string
	DataDir             string
	DevMode             bool

	// address values

	BindAddrs         []string
	ClientAddr        string
	StartJoinAddrsLAN []string

	// server endpoint values

	DNSPort     int
	DNSAddrsTCP []string
	DNSAddrsUDP []string

	// other values

	NodeMeta map[string]string
}

// NewRuntimeConfig creates the runtime configuration from a configuration
// file. It performs all the necessary syntactic and semantic validation
// so that the resulting runtime configuration is usable.
func NewRuntimeConfig(f Config) (RuntimeConfig, error) {
	return (&builder{f: f}).build()
}

type builder struct {
	f     Config
	err   error
	warns []error
}

func (b *builder) build() (RuntimeConfig, error) {
	f := b.f

	var c RuntimeConfig

	// ACL
	c.ACLAgentMasterToken = b.stringVal(f.ACLAgentMasterToken)
	c.ACLAgentToken = b.stringVal(f.ACLAgentToken)
	c.ACLDatacenter = b.stringVal(f.ACLDatacenter)
	c.ACLDefaultPolicy = b.stringVal(f.ACLDefaultPolicy)
	c.ACLDownPolicy = b.stringVal(f.ACLDownPolicy)
	c.ACLEnforceVersion8 = b.boolVal(f.ACLEnforceVersion8)
	c.ACLMasterToken = b.stringVal(f.ACLMasterToken)
	c.ACLReplicationToken = b.stringVal(f.ACLReplicationToken)
	c.ACLTTL = b.durationVal(f.ACLTTL)
	c.ACLToken = b.stringVal(f.ACLToken)

	// Autopilot
	c.AutopilotCleanupDeadServers = b.boolVal(f.Autopilot.CleanupDeadServers)
	c.AutopilotDisableUpgradeMigration = b.boolVal(f.Autopilot.DisableUpgradeMigration)
	c.AutopilotLastContactThreshold = b.durationVal(f.Autopilot.LastContactThreshold)
	if n := b.intVal(f.Autopilot.MaxTrailingLogs); n < 0 {
		return c, fmt.Errorf("config: autopilot.max_trailing_logs < 0")
	} else {
		c.AutopilotMaxTrailingLogs = uint64(n)
	}
	c.AutopilotRedundancyZoneTag = b.stringVal(f.Autopilot.RedundancyZoneTag)
	c.AutopilotServerStabilizationTime = b.durationVal(f.Autopilot.ServerStabilizationTime)
	c.AutopilotUpgradeVersionTag = b.stringVal(f.Autopilot.UpgradeVersionTag)

	// DNS
	c.DNSAllowStale = b.boolVal(f.DNS.AllowStale)
	c.DNSDisableCompression = b.boolVal(f.DNS.DisableCompression)
	c.DNSDomain = b.stringVal(f.DNSDomain)
	c.DNSEnableTruncate = b.boolVal(f.DNS.EnableTruncate)
	c.DNSMaxStale = b.durationVal(f.DNS.MaxStale)
	c.DNSNodeTTL = b.durationVal(f.DNS.NodeTTL)
	c.DNSOnlyPassing = b.boolVal(f.DNS.OnlyPassing)
	if f.DNSRecursor != nil {
		c.DNSRecursors = append(c.DNSRecursors, b.stringVal(f.DNSRecursor))
	}
	c.DNSRecursors = append(c.DNSRecursors, f.DNSRecursors...)
	c.DNSRecursorTimeout = b.durationVal(f.DNS.RecursorTimeout)
	c.DNSServiceTTL = map[string]time.Duration{}
	for k, v := range f.DNS.ServiceTTL {
		c.DNSServiceTTL[k] = b.durationVal(&v)
	}
	c.DNSUDPAnswerLimit = b.intVal(f.DNS.UDPAnswerLimit)

	// HTTP

	// Performance

	// Telemetry

	// RetryJoinAzure

	// RetryJoinEC2

	// RetryJoinGCE

	// UnixSocket

	// Agent
	c.Bootstrap = b.boolVal(f.Bootstrap)
	c.BootstrapExpect = b.intVal(f.BootstrapExpect)
	c.CAFile = b.stringVal(f.CAFile)
	c.CAPath = b.stringVal(f.CAPath)
	c.CertFile = b.stringVal(f.CertFile)
	c.CheckUpdateInterval = b.durationVal(f.CheckUpdateInterval)
	c.Datacenter = b.stringVal(f.Datacenter)
	c.DataDir = b.stringVal(f.DataDir)
	c.DevMode = b.boolVal(f.DevMode)
	c.NodeMeta = f.NodeMeta
	c.StartJoinAddrsLAN = f.StartJoinAddrsLAN

	// Checks and Services
	if f.Check != nil {
		c.Checks = append(c.Checks, b.checkVal(f.Check))
	}
	for _, check := range f.Checks {
		c.Checks = append(c.Checks, b.checkVal(&check))
	}

	// Addresses

	c.ClientAddr = b.stringVal(f.ClientAddr)

	// if no bind address is given but ports are specified then we bail.
	// this only affects tests since in prod this gets merged with the
	// default config which always has a bind address.
	if f.BindAddr == nil && !reflect.DeepEqual(f.Ports, Ports{}) {
		return RuntimeConfig{}, fmt.Errorf("no bind address specified")
	}

	if f.BindAddr != nil {
		c.BindAddrs = []string{b.addrVal(f.BindAddr)}
	}

	if f.Ports.DNS != nil {
		c.DNSPort = b.intVal(f.Ports.DNS)
		for _, addr := range c.BindAddrs {
			c.DNSAddrsTCP = append(c.DNSAddrsTCP, b.joinHostPort(addr, c.DNSPort))
			c.DNSAddrsUDP = append(c.DNSAddrsUDP, b.joinHostPort(addr, c.DNSPort))
		}
	}

	return c, b.err
}

func (b *builder) warn(msg string, args ...interface{}) {
	b.warns = append(b.warns, fmt.Errorf(msg, args...))
}

func (b *builder) checkVal(v *CheckDefinition) *structs.CheckDefinition {
	if b.err != nil || v == nil {
		return nil
	}

	serviceID := v.ServiceID
	if v.AliasServiceID != nil {
		b.warn("config: 'serviceid' is deprecated in check definitions. Please use 'service_id' instead")
		serviceID = v.AliasServiceID
	}

	dockerContainerID := v.DockerContainerID
	if v.AliasDockerContainerID != nil {
		b.warn("config: 'dockercontainerid' is deprecated in check definitions. Please use 'docker_container_id' instead")
		dockerContainerID = v.AliasDockerContainerID
	}

	tlsSkipVerify := v.TLSSkipVerify
	if v.AliasTLSSkipVerify != nil {
		b.warn("config: 'tlsskipverify' is deprecated in check definitions. Please use 'tls_skip_verify' instead")
		tlsSkipVerify = v.AliasTLSSkipVerify
	}

	deregisterCriticalServiceAfter := v.DeregisterCriticalServiceAfter
	if v.AliasDeregisterCriticalServiceAfter != nil {
		b.warn("config: 'deregistercriticalserviceafter' is deprecated in check definitions. Please use 'deregister_critical_service_after' instead")
		deregisterCriticalServiceAfter = v.AliasDeregisterCriticalServiceAfter
	}

	return &structs.CheckDefinition{
		ID:                types.CheckID(b.stringVal(v.ID)),
		Name:              b.stringVal(v.Name),
		Notes:             b.stringVal(v.Notes),
		ServiceID:         b.stringVal(serviceID),
		Token:             b.stringVal(v.Token),
		Status:            b.stringVal(v.Status),
		Script:            b.stringVal(v.Script),
		HTTP:              b.stringVal(v.HTTP),
		Header:            v.Header,
		Method:            b.stringVal(v.Method),
		TCP:               b.stringVal(v.TCP),
		Interval:          b.durationVal(v.Interval),
		DockerContainerID: b.stringVal(dockerContainerID),
		Shell:             b.stringVal(v.Shell),
		TLSSkipVerify:     b.boolVal(tlsSkipVerify),
		Timeout:           b.durationVal(v.Timeout),
		TTL:               b.durationVal(v.TTL),
		DeregisterCriticalServiceAfter: b.durationVal(deregisterCriticalServiceAfter),
	}
}

func (b *builder) boolVal(v *bool) bool {
	if b.err != nil || v == nil {
		return false
	}
	return *v
}

func (b *builder) durationVal(v *string) (d time.Duration) {
	if b.err != nil || v == nil {
		return 0
	}
	d, b.err = time.ParseDuration(*v)
	return
}

func (b *builder) intVal(v *int) int {
	if b.err != nil || v == nil {
		return 0
	}
	return *v
}

func (b *builder) uint64Val(v *uint64) uint64 {
	if b.err != nil || v == nil {
		return 0
	}
	return *v
}

func (b *builder) stringVal(v *string) string {
	if b.err != nil || v == nil {
		return ""
	}
	return *v
}

func (b *builder) addrVal(v *string) string {
	addr := b.stringVal(v)
	if addr == "" {
		return "0.0.0.0"
	}
	return addr
}

func (b *builder) joinHostPort(host string, port int) string {
	if host == "0.0.0.0" {
		host = ""
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}
