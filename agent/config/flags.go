package config

import (
	"flag"
	"fmt"
	"time"
)

// Flags defines the command line flags.
type Flags struct {
	Config      Config
	ConfigFiles []string

	DeprecatedDatacenter          *string
	DeprecatedAtlasInfrastructure *string
	DeprecatedAtlasJoin           *bool
	DeprecatedAtlasToken          *string
	DeprecatedAtlasEndpoint       *string
}

// ParseFlag parses the arguments into a Flags struct.
func ParseFlags(args []string) (Flags, error) {
	var f Flags
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	AddFlags(fs, &f)
	if err := fs.Parse(args); err != nil {
		return Flags{}, err
	}
	return f, nil
}

// AddFlags adds the command line flags for the agent.
func AddFlags(fs *flag.FlagSet, f *Flags) {
	add := func(p interface{}, name, help string) {
		switch x := p.(type) {
		case **bool:
			fs.Var(newBoolPtrValue(x), name, help)
		case **time.Duration:
			fs.Var(newDurationPtrValue(x), name, help)
		case **int:
			fs.Var(newIntPtrValue(x), name, help)
		case **string:
			fs.Var(newStringPtrValue(x), name, help)
		case *[]string:
			fs.Var(newStringSliceValue(x), name, help)
		case *map[string]string:
			fs.Var(newStringMapValue(x), name, help)
		default:
			panic(fmt.Sprintf("invalid type: %T", p))
		}
	}

	// command line flags ordered by flag name
	add(&f.Config.AdvertiseAddrLAN, "advertise", "Sets the advertise address to use.")
	add(&f.Config.AdvertiseAddrWAN, "advertise-wan", "Sets address to advertise on WAN instead of -advertise address.")
	add(&f.Config.BindAddr, "bind", "Sets the bind address for cluster communication.")
	add(&f.Config.Bootstrap, "bootstrap", "Sets server to bootstrap mode.")
	add(&f.Config.BootstrapExpect, "bootstrap-expect", "Sets server to expect bootstrap mode.")
	add(&f.Config.ClientAddr, "client", "Sets the address to bind for client access. This includes RPC, DNS, HTTP and HTTPS (if configured).")
	add(&f.ConfigFiles, "config-dir", "Path to a directory to read configuration files from. This will read every file ending in '.json' as configuration in this directory in alphabetical order. Can be specified multiple times.")
	add(&f.ConfigFiles, "config-file", "Path to a JSON file to read configuration from. Can be specified multiple times.")
	add(&f.Config.DataDir, "data-dir", "Path to a data directory to store agent state.")
	add(&f.Config.Datacenter, "datacenter", "Datacenter of the agent.")
	add(&f.Config.DevMode, "dev", "Starts the agent in development mode.")
	add(&f.Config.DisableHostNodeID, "disable-host-node-id", "Setting this to true will prevent Consul from using information from the host to generate a node ID, and will cause Consul to generate a random node ID instead.")
	add(&f.Config.DisableKeyringFile, "disable-keyring-file", "Disables the backing up of the keyring to a file.")
	add(&f.Config.Ports.DNS, "dns-port", "DNS port to use.")
	add(&f.Config.DNSDomain, "domain", "Domain to use for DNS interface.")
	add(&f.Config.EnableScriptChecks, "enable-script-checks", "Enables health check scripts.")
	add(&f.Config.EncryptKey, "encrypt", "Provides the gossip encryption key.")
	add(&f.Config.Ports.HTTP, "http-port", "Sets the HTTP API port to listen on.")
	add(&f.Config.StartJoinAddrsLAN, "join", "Address of an agent to join at start time. Can be specified multiple times.")
	add(&f.Config.StartJoinAddrsWAN, "join-wan", "Address of an agent to join -wan at start time. Can be specified multiple times.")
	add(&f.Config.LogLevel, "log-level", "Log level of the agent.")
	add(&f.Config.NodeName, "node", "Name of this node. Must be unique in the cluster.")
	add(&f.Config.NodeID, "node-id", "A unique ID for this node across space and time. Defaults to a randomly-generated ID that persists in the data-dir.")
	add(&f.Config.NodeMeta, "node-meta", "An arbitrary metadata key/value pair for this node, of the format `key:value`. Can be specified multiple times.")
	add(&f.Config.NonVotingServer, "non-voting-server", "(Enterprise-only) This flag is used to make the server not participate in the Raft quorum, and have it only receive the data replication stream. This can be used to add read scalability to a cluster in cases where a high volume of reads to servers are needed.")
	add(&f.Config.PidFile, "pid-file", "Path to file to store agent PID.")
	add(&f.Config.RPCProtocol, "protocol", "Sets the protocol version. Defaults to latest.")
	add(&f.Config.RaftProtocol, "raft-protocol", "Sets the Raft protocol version. Defaults to latest.")
	add(&f.Config.DNSRecursors, "recursor", "Address of an upstream DNS server. Can be specified multiple times.")
	add(&f.Config.RejoinAfterLeave, "rejoin", "Ignores a previous leave and attempts to rejoin the cluster.")
	add(&f.Config.RetryJoinIntervalLAN, "retry-interval", "Time to wait between join attempts.")
	add(&f.Config.RetryJoinIntervalWAN, "retry-interval-wan", "Time to wait between join -wan attempts.")
	add(&f.Config.RetryJoinLAN, "retry-join", "Address of an agent to join at start time with retries enabled. Can be specified multiple times.")
	add(&f.Config.RetryJoinWAN, "retry-join-wan", "Address of an agent to join -wan at start time with retries enabled. Can be specified multiple times.")
	add(&f.Config.RetryJoinMaxAttemptsLAN, "retry-max", "Maximum number of join attempts. Defaults to 0, which will retry indefinitely.")
	add(&f.Config.RetryJoinMaxAttemptsWAN, "retry-max-wan", "Maximum number of join -wan attempts. Defaults to 0, which will retry indefinitely.")
	add(&f.Config.SerfBindAddrLAN, "serf-lan-bind", "Address to bind Serf LAN listeners to.")
	add(&f.Config.SerfBindAddrWAN, "serf-wan-bind", "Address to bind Serf WAN listeners to.")
	add(&f.Config.ServerMode, "server", "Switches agent to server mode.")
	add(&f.Config.EnableSyslog, "syslog", "Enables logging to syslog.")
	add(&f.Config.EnableUI, "ui", "Enables the built-in static web UI server.")
	add(&f.Config.UIDir, "ui-dir", "Path to directory containing the web UI resources.")

	// deprecated flags orderd by flag name
	add(&f.DeprecatedAtlasInfrastructure, "atlas", "(deprecated) Sets the Atlas infrastructure name, enables SCADA.")
	add(&f.DeprecatedAtlasEndpoint, "atlas-endpoint", "(deprecated) The address of the endpoint for Atlas integration.")
	add(&f.DeprecatedAtlasJoin, "atlas-join", "(deprecated) Enables auto-joining the Atlas cluster.")
	add(&f.DeprecatedAtlasToken, "atlas-token", "(deprecated) Provides the Atlas API token.")
	add(&f.DeprecatedDatacenter, "dc", "(deprecated) Datacenter of the agent (use 'datacenter' instead).")
	add(&f.Config.DeprecatedRetryJoinAzure.TagName, "retry-join-azure-tag-name", "Azure tag name to filter on for server discovery.")
	add(&f.Config.DeprecatedRetryJoinAzure.TagValue, "retry-join-azure-tag-value", "Azure tag value to filter on for server discovery.")
	add(&f.Config.DeprecatedRetryJoinEC2.Region, "retry-join-ec2-region", "EC2 Region to discover servers in.")
	add(&f.Config.DeprecatedRetryJoinEC2.TagKey, "retry-join-ec2-tag-key", "EC2 tag key to filter on for server discovery.")
	add(&f.Config.DeprecatedRetryJoinEC2.TagValue, "retry-join-ec2-tag-value", "EC2 tag value to filter on for server discovery.")
	add(&f.Config.DeprecatedRetryJoinGCE.CredentialsFile, "retry-join-gce-credentials-file", "Path to credentials JSON file to use with Google Compute Engine.")
	add(&f.Config.DeprecatedRetryJoinGCE.ProjectName, "retry-join-gce-project-name", "Google Compute Engine project to discover servers in.")
	add(&f.Config.DeprecatedRetryJoinGCE.TagValue, "retry-join-gce-tag-value", "Google Compute Engine tag value to filter on for server discovery.")
	add(&f.Config.DeprecatedRetryJoinGCE.ZonePattern, "retry-join-gce-zone-pattern", "Google Compute Engine region or zone to discover servers in (regex pattern).")
}
