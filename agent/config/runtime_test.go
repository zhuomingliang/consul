package config

import (
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/consul/agent/structs"
	"github.com/hashicorp/consul/types"
	"github.com/pascaldekloe/goe/verify"
)

// TestRuntimeConfig tests whether a combination of command line flags and
// config files creates the correct runtime configuration. The tests do
// not use the default configuration as basis as this would provide a
// lot of redundancy in the test results.
//
// The tests are grouped and within the groups are ordered alphabetically.
func TestRuntimeConfig(t *testing.T) {
	tests := []struct {
		desc             string
		def              Config
		json, hcl, flags []string
		rtcfg            RuntimeConfig
		err              error
	}{
		{
			desc:  "default config",
			def:   defaultConfig,
			rtcfg: defaultRuntimeConfig,
		},

		// cmd line flags
		{
			desc:  "-bind",
			flags: []string{`-bind`, `1.2.3.4`},
			rtcfg: RuntimeConfig{BindAddrs: []string{"1.2.3.4"}},
		},
		{
			desc:  "-bootstrap",
			flags: []string{`-bootstrap`},
			rtcfg: RuntimeConfig{Bootstrap: true},
		},
		{
			desc:  "-datacenter",
			flags: []string{`-datacenter`, `a`},
			rtcfg: RuntimeConfig{Datacenter: "a"},
		},
		{
			desc:  "-dns-port",
			flags: []string{`-dns-port`, `123`, `-bind`, `0.0.0.0`},
			rtcfg: RuntimeConfig{
				BindAddrs:   []string{"0.0.0.0"},
				DNSPort:     123,
				DNSAddrsUDP: []string{":123"},
				DNSAddrsTCP: []string{":123"},
			},
		},
		{
			desc:  "-join",
			flags: []string{`-join`, `a`, `-join`, `b`},
			rtcfg: RuntimeConfig{StartJoinAddrsLAN: []string{"a", "b"}},
		},
		{
			desc:  "-node-meta",
			flags: []string{`-node-meta`, `a:b`, `-node-meta`, `c:d`},
			rtcfg: RuntimeConfig{NodeMeta: map[string]string{"a": "b", "c": "d"}},
		},

		// cfg files
		{
			desc:  "acl_agent_master_token",
			json:  []string{`{"acl_agent_master_token":"a"}`},
			hcl:   []string{`acl_agent_master_token = "a"`},
			rtcfg: RuntimeConfig{ACLAgentMasterToken: "a"},
		},
		{
			desc:  "acl_agent_token",
			json:  []string{`{"acl_agent_token":"a"}`},
			hcl:   []string{`acl_agent_token = "a"`},
			rtcfg: RuntimeConfig{ACLAgentToken: "a"},
		},
		{
			desc:  "acl_datacenter",
			json:  []string{`{"acl_datacenter":"a"}`},
			hcl:   []string{`acl_datacenter = "a"`},
			rtcfg: RuntimeConfig{ACLDatacenter: "a"},
		},
		{
			desc:  "acl_default_policy",
			json:  []string{`{"acl_default_policy":"a"}`},
			hcl:   []string{`acl_default_policy = "a"`},
			rtcfg: RuntimeConfig{ACLDefaultPolicy: "a"},
		},
		{
			desc:  "acl_down_policy",
			json:  []string{`{"acl_down_policy":"a"}`},
			hcl:   []string{`acl_down_policy = "a"`},
			rtcfg: RuntimeConfig{ACLDownPolicy: "a"},
		},
		{
			desc:  "acl_enforce_version_8",
			json:  []string{`{"acl_enforce_version_8":true}`},
			hcl:   []string{`acl_enforce_version_8 = true`},
			rtcfg: RuntimeConfig{ACLEnforceVersion8: true},
		},
		{
			desc:  "acl_master_token",
			json:  []string{`{"acl_master_token":"a"}`},
			hcl:   []string{`acl_master_token = "a"`},
			rtcfg: RuntimeConfig{ACLMasterToken: "a"},
		},
		{
			desc:  "acl_replication_token",
			json:  []string{`{"acl_replication_token":"a"}`},
			hcl:   []string{`acl_replication_token = "a"`},
			rtcfg: RuntimeConfig{ACLReplicationToken: "a"},
		},
		{
			desc:  "acl_ttl",
			json:  []string{`{"acl_ttl":"5s"}`},
			hcl:   []string{`acl_ttl = "5s"`},
			rtcfg: RuntimeConfig{ACLTTL: 5 * time.Second},
		},
		{
			desc:  "acl_token",
			json:  []string{`{"acl_token":"a"}`},
			hcl:   []string{`acl_token = "a"`},
			rtcfg: RuntimeConfig{ACLToken: "a"},
		},
		{
			desc:  "autopilot.cleanup_dead_servers",
			json:  []string{`{"autopilot":{"cleanup_dead_servers":true}}`},
			hcl:   []string{`autopilot { cleanup_dead_servers = true}`},
			rtcfg: RuntimeConfig{AutopilotCleanupDeadServers: true},
		},
		{
			desc:  "autopilot.disable_upgrade_migration",
			json:  []string{`{"autopilot":{"disable_upgrade_migration":true}}`},
			hcl:   []string{`autopilot { disable_upgrade_migration = true}`},
			rtcfg: RuntimeConfig{AutopilotDisableUpgradeMigration: true},
		},
		{
			desc:  "autopilot.last_contact_threshold",
			json:  []string{`{"autopilot":{"last_contact_threshold":"5s"}}`},
			hcl:   []string{`autopilot { last_contact_threshold = "5s"}`},
			rtcfg: RuntimeConfig{AutopilotLastContactThreshold: 5 * time.Second},
		},
		{
			desc:  "autopilot.max_trailing_logs",
			json:  []string{`{"autopilot":{"max_trailing_logs":1}}`},
			hcl:   []string{`autopilot { max_trailing_logs = 1}`},
			rtcfg: RuntimeConfig{AutopilotMaxTrailingLogs: 1},
		},
		{
			desc:  "autopilot.redundancy_zone_tag",
			json:  []string{`{"autopilot":{"redundancy_zone_tag":"a"}}`},
			hcl:   []string{`autopilot { redundancy_zone_tag = "a"}`},
			rtcfg: RuntimeConfig{AutopilotRedundancyZoneTag: "a"},
		},
		{
			desc:  "autopilot.server_stabilization_time",
			json:  []string{`{"autopilot":{"server_stabilization_time":"5s"}}`},
			hcl:   []string{`autopilot { server_stabilization_time = "5s"}`},
			rtcfg: RuntimeConfig{AutopilotServerStabilizationTime: 5 * time.Second},
		},
		{
			desc:  "autopilot.upgrade_version_tag",
			json:  []string{`{"autopilot":{"upgrade_version_tag":"a"}}`},
			hcl:   []string{`autopilot { upgrade_version_tag = "a"}`},
			rtcfg: RuntimeConfig{AutopilotUpgradeVersionTag: "a"},
		},
		{
			desc:  "bind_addr",
			json:  []string{`{"bind_addr":"0.0.0.0"}`},
			hcl:   []string{`bind_addr = "0.0.0.0"`},
			rtcfg: RuntimeConfig{BindAddrs: []string{"0.0.0.0"}},
		},
		{
			desc:  "bootstrap",
			json:  []string{`{"bootstrap":true}`},
			hcl:   []string{`bootstrap = true`},
			rtcfg: RuntimeConfig{Bootstrap: true},
		},
		{
			desc:  "bootstrap_expect",
			json:  []string{`{"bootstrap_expect":1}`},
			hcl:   []string{`bootstrap_expect = 1`},
			rtcfg: RuntimeConfig{BootstrapExpect: 1},
		},
		{
			desc:  "ca_file",
			json:  []string{`{"ca_file":"a"}`},
			hcl:   []string{`ca_file = "a"`},
			rtcfg: RuntimeConfig{CAFile: "a"},
		},
		{
			desc:  "ca_path",
			json:  []string{`{"ca_path":"a"}`},
			hcl:   []string{`ca_path = "a"`},
			rtcfg: RuntimeConfig{CAPath: "a"},
		},
		{
			desc:  "cert_file",
			json:  []string{`{"cert_file":"a"}`},
			hcl:   []string{`cert_file = "a"`},
			rtcfg: RuntimeConfig{CertFile: "a"},
		},
		{
			desc:  "check_update_interval",
			json:  []string{`{"check_update_interval":"5m"}`},
			hcl:   []string{`check_update_interval = "5m"`},
			rtcfg: RuntimeConfig{CheckUpdateInterval: 5 * time.Minute},
		},
		{
			desc: "check alias fields",
			json: []string{`{"check":{ "service_id":"d", "serviceid":"dd", "docker_container_id":"k", "dockercontainerid":"kk", "tls_skip_verify":true, "tlsskipverify":false, "deregister_critical_service_after":"5s", "deregistercriticalserviceafter": "10s" }}`},
			hcl:  []string{`check = { service_id="d" serviceid="dd" docker_container_id="k" dockercontainerid="kk" tls_skip_verify=true tlsskipverify=false deregister_critical_service_after="5s" deregistercriticalserviceafter="10s"}`},
			rtcfg: RuntimeConfig{Checks: []*structs.CheckDefinition{
				{
					ServiceID:                      "dd",
					DockerContainerID:              "kk",
					TLSSkipVerify:                  false,
					DeregisterCriticalServiceAfter: 10 * time.Second,
				},
			}},
		},
		{
			desc: "check",
			json: []string{`{"check":{ "id":"a", "name":"b", "notes":"c", "service_id":"d", "token":"e", "status":"f", "script":"g", "http":"h", "header":{"x":["y"]}, "method":"i", "tcp":"j", "interval":"5s", "docker_container_id":"k", "shell":"l", "tls_skip_verify":true, "timeout":"5s", "ttl":"5s", "deregister_critical_service_after":"5s" }}`},
			hcl:  []string{`check = { id="a" name="b" notes="c" service_id="d" token="e" status="f" script="g" http="h" header={x=["y"]} method="i" tcp="j" interval="5s" docker_container_id="k" shell="l" tls_skip_verify=true timeout="5s" ttl="5s" deregister_critical_service_after="5s" }`},
			rtcfg: RuntimeConfig{Checks: []*structs.CheckDefinition{
				{
					ID:                types.CheckID("a"),
					Name:              "b",
					Notes:             "c",
					ServiceID:         "d",
					Token:             "e",
					Status:            "f",
					Script:            "g",
					HTTP:              "h",
					Header:            map[string][]string{"x": []string{"y"}},
					Method:            "i",
					TCP:               "j",
					Interval:          5 * time.Second,
					DockerContainerID: "k",
					Shell:             "l",
					TLSSkipVerify:     true,
					Timeout:           5 * time.Second,
					TTL:               5 * time.Second,
					DeregisterCriticalServiceAfter: 5 * time.Second,
				},
			}},
		},
		{
			desc: "checks",
			json: []string{`{"checks":[{ "id":"a", "name":"b", "notes":"c", "service_id":"d", "token":"e", "status":"f", "script":"g", "http":"h", "header":{"x":["y"]}, "method":"i", "tcp":"j", "interval":"5s", "docker_container_id":"k", "shell":"l", "tls_skip_verify":true, "timeout":"5s", "ttl":"5s", "deregister_critical_service_after":"5s" }]}`},
			hcl:  []string{`checks = [{ id="a" name="b" notes="c" service_id="d" token="e" status="f" script="g" http="h" header={x=["y"]} method="i" tcp="j" interval="5s" docker_container_id="k" shell="l" tls_skip_verify=true timeout="5s" ttl="5s" deregister_critical_service_after="5s" }]`},
			rtcfg: RuntimeConfig{Checks: []*structs.CheckDefinition{
				{
					ID:                types.CheckID("a"),
					Name:              "b",
					Notes:             "c",
					ServiceID:         "d",
					Token:             "e",
					Status:            "f",
					Script:            "g",
					HTTP:              "h",
					Header:            map[string][]string{"x": []string{"y"}},
					Method:            "i",
					TCP:               "j",
					Interval:          5 * time.Second,
					DockerContainerID: "k",
					Shell:             "l",
					TLSSkipVerify:     true,
					Timeout:           5 * time.Second,
					TTL:               5 * time.Second,
					DeregisterCriticalServiceAfter: 5 * time.Second,
				},
			}},
		},
		{
			desc:  "client_addr",
			json:  []string{`{"client_addr":"a"}`},
			hcl:   []string{`client_addr = "a"`},
			rtcfg: RuntimeConfig{ClientAddr: "a"},
		},
		{
			desc:  "dns_config.allow_stale",
			json:  []string{`{"dns_config":{"allow_stale":true}}`},
			hcl:   []string{`dns_config = { allow_stale=true }`},
			rtcfg: RuntimeConfig{DNSAllowStale: true},
		},
		{
			desc:  "dns_config.disable_compression",
			json:  []string{`{"dns_config":{"disable_compression":true}}`},
			hcl:   []string{`dns_config = { disable_compression=true }`},
			rtcfg: RuntimeConfig{DNSDisableCompression: true},
		},
		{
			desc:  "dns_config.enable_truncate",
			json:  []string{`{"dns_config":{"enable_truncate":true}}`},
			hcl:   []string{`dns_config = { enable_truncate=true }`},
			rtcfg: RuntimeConfig{DNSEnableTruncate: true},
		},
		{
			desc:  "dns_config.max_stale",
			json:  []string{`{"dns_config":{"max_stale":"5s"}}`},
			hcl:   []string{`dns_config = { max_stale="5s" }`},
			rtcfg: RuntimeConfig{DNSMaxStale: 5 * time.Second},
		},
		{
			desc:  "dns_config.node_ttl",
			json:  []string{`{"dns_config":{"node_ttl":"5s"}}`},
			hcl:   []string{`dns_config = { node_ttl="5s" }`},
			rtcfg: RuntimeConfig{DNSNodeTTL: 5 * time.Second},
		},
		{
			desc:  "dns_config.only_passing",
			json:  []string{`{"dns_config":{"only_passing":true}}`},
			hcl:   []string{`dns_config = { only_passing=true }`},
			rtcfg: RuntimeConfig{DNSOnlyPassing: true},
		},
		{
			desc:  "dns_config.recursor_timeout",
			json:  []string{`{"dns_config":{"recursor_timeout":"5s"}}`},
			hcl:   []string{`dns_config = { recursor_timeout="5s" }`},
			rtcfg: RuntimeConfig{DNSRecursorTimeout: 5 * time.Second},
		},
		{
			desc:  "dns_config.service_ttl",
			json:  []string{`{"dns_config":{"service_ttl":{"a":"5s", "*":"10s"}}}`},
			hcl:   []string{`dns_config = { service_ttl={ a="5s" "*"="10s" } }`},
			rtcfg: RuntimeConfig{DNSServiceTTL: map[string]time.Duration{"a": 5 * time.Second, "*": 10 * time.Second}},
		},
		{
			desc:  "dns_config.udp_answer_limit",
			json:  []string{`{"dns_config":{"udp_answer_limit":1}}`},
			hcl:   []string{`dns_config = { udp_answer_limit=1 }`},
			rtcfg: RuntimeConfig{DNSUDPAnswerLimit: 1},
		},
		{
			desc:  "recursor",
			json:  []string{`{"recursor":"a"}`},
			hcl:   []string{`recursor = "a"`},
			rtcfg: RuntimeConfig{DNSRecursors: []string{"a"}},
		},
		{
			desc:  "recursors",
			json:  []string{`{"recursors":["a","b"]}`},
			hcl:   []string{`recursors = ["a","b"]`},
			rtcfg: RuntimeConfig{DNSRecursors: []string{"a", "b"}},
		},
		{
			desc:  "recursor and recursors",
			json:  []string{`{"recursor":"a", "recursors":["b","c"]}`},
			hcl:   []string{`recursor="a" recursors=["b","c"]`},
			rtcfg: RuntimeConfig{DNSRecursors: []string{"a", "b", "c"}},
		},
		{
			desc:  "domain",
			json:  []string{`{"domain":"a"}`},
			hcl:   []string{`domain = "a"`},
			rtcfg: RuntimeConfig{DNSDomain: "a"},
		},
		{
			desc:  "datacenter",
			json:  []string{`{"datacenter":"a"}`},
			hcl:   []string{`datacenter = "a"`},
			rtcfg: RuntimeConfig{Datacenter: "a"},
		},
		{
			desc:  "data_dir",
			json:  []string{`{"data_dir":"a"}`},
			hcl:   []string{`data_dir = "a"`},
			rtcfg: RuntimeConfig{DataDir: "a"},
		},
		{
			desc:  "dev",
			json:  []string{`{"dev":true}`},
			hcl:   []string{`dev= true`},
			rtcfg: RuntimeConfig{DevMode: true},
		},
		{
			desc:  "start_join",
			json:  []string{`{"start_join":["a"]}`, `{"start_join":["b"]}`},
			hcl:   []string{`start_join = ["a"]`, `start_join = ["b"]`},
			rtcfg: RuntimeConfig{StartJoinAddrsLAN: []string{"a", "b"}},
		},
		{
			desc:  "node_meta",
			json:  []string{`{"node_meta":{"a":"b"}}`},
			hcl:   []string{`node_meta { a = "b" }`},
			rtcfg: RuntimeConfig{NodeMeta: map[string]string{"a": "b"}},
		},
		{
			desc:  "node_meta merge",
			json:  []string{`{"node_meta":{"a":"b"}}`, `{"node_meta":{"c":"d"}}`},
			hcl:   []string{`node_meta { a = "b" }`, `node_meta { c = "d" }`},
			rtcfg: RuntimeConfig{NodeMeta: map[string]string{"c": "d"}},
		},
		{
			desc: "ports.dns",
			json: []string{`{"bind_addr":"0.0.0.0","ports":{"dns":123}}`},
			hcl:  []string{`bind_addr = "0.0.0.0" ports { dns = 123 }`},
			rtcfg: RuntimeConfig{
				BindAddrs:   []string{"0.0.0.0"},
				DNSPort:     123,
				DNSAddrsUDP: []string{":123"},
				DNSAddrsTCP: []string{":123"},
			},
		},

		// precedence rules
		{
			desc:  "precedence: bool val",
			json:  []string{`{"bootstrap":true}`, `{"bootstrap":false}`},
			hcl:   []string{`bootstrap = true`, `bootstrap = false`},
			rtcfg: RuntimeConfig{Bootstrap: false},
		},
		{
			desc:  "precedence: flag before file",
			json:  []string{`{"bootstrap":true}`},
			hcl:   []string{`bootstrap = true`},
			flags: []string{`-bootstrap=false`},
			rtcfg: RuntimeConfig{Bootstrap: false},
		},
	}

	for _, tt := range tests {
		for _, format := range []string{"json", "hcl"} {
			if len(tt.json) != len(tt.hcl) {
				t.Fatal("JSON and HCL test case out of sync")
			}

			files := tt.json
			if format == "hcl" {
				files = tt.hcl
			}

			// ugly hack to skip second run for flag-only tests
			if len(files) == 0 && format == "hcl" {
				continue
			}

			var desc []string
			if len(files) > 0 {
				desc = append(desc, format)
			}
			if tt.desc != "" {
				desc = append(desc, tt.desc)
			}
			// if len(files) > 0 {
			// 	desc = append(desc, strings.Join(files, ",")
			// }
			// if len(tt.flags) > 0 {
			// 	s := "flags:" + strings.Join(tt.flags, " ")
			// 	desc = append(desc, s)
			// }

			t.Run(strings.Join(desc, ":"), func(t *testing.T) {
				// start with default config
				cfgs := []Config{tt.def}

				// add files in order
				for _, s := range files {
					f, err := ParseFile(s, format)
					if err != nil {
						t.Fatalf("ParseFile failed for %q: %s", s, err)
					}
					cfgs = append(cfgs, f)
				}

				// add flags
				flags, err := ParseFlags(tt.flags)
				if err != nil {
					t.Fatalf("ParseFlags failed: %s", err)
				}
				cfgs = append(cfgs, flags.Config)

				// merge files and build config
				rtcfg, err := NewRuntimeConfig(Merge(cfgs))
				if err != nil {
					t.Fatalf("NewConfig failed: %s", err)
				}

				if !verify.Values(t, "", rtcfg, tt.rtcfg) {
					t.FailNow()
				}
			})
		}
	}
}
