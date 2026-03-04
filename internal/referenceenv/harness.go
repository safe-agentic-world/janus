package referenceenv

import "strings"

type Check struct {
	ID      string
	OK      bool
	Details string
}

type Report struct {
	Checks []Check
}

func (r Report) AllPassed() bool {
	for _, check := range r.Checks {
		if !check.OK {
			return false
		}
	}
	return true
}

func ValidateStrongGuaranteeManifest(manifest string) Report {
	checks := make([]Check, 0, 14)
	appendCheck := func(id, details string, ok bool) {
		checks = append(checks, Check{
			ID:      id,
			OK:      ok,
			Details: details,
		})
	}

	agentDeployment, agentFound := findManifestDoc(manifest, "kind: Deployment", "name: sample-agent")
	appendCheck("sample_agent.deployment_present", "sample-agent deployment exists", agentFound)
	if agentFound {
		appendCheck("sample_agent.service_account_bound", "sample-agent uses dedicated service account", strings.Contains(agentDeployment, "serviceAccountName: sample-agent"))
		appendCheck("sample_agent.service_account_token_disabled", "sample-agent disables automounted service account tokens", strings.Contains(agentDeployment, "automountServiceAccountToken: false"))
		appendCheck("sample_agent.run_as_non_root", "sample-agent runs as non-root", strings.Contains(agentDeployment, "runAsNonRoot: true"))
		appendCheck("sample_agent.read_only_root_fs", "sample-agent uses readonly root filesystem", strings.Contains(agentDeployment, "readOnlyRootFilesystem: true"))
		appendCheck("sample_agent.no_privilege_escalation", "sample-agent disables privilege escalation", strings.Contains(agentDeployment, "allowPrivilegeEscalation: false"))
		appendCheck("sample_agent.no_host_path", "sample-agent avoids hostPath mounts", !strings.Contains(agentDeployment, "hostPath:"))
		appendCheck("sample_agent.no_secret_mounts", "sample-agent avoids direct secret mounts", !strings.Contains(agentDeployment, "secretKeyRef:") && !strings.Contains(agentDeployment, "secret:") && !strings.Contains(agentDeployment, "projected:"))
	}

	agentPolicy, policyFound := findManifestDoc(manifest, "kind: NetworkPolicy", "name: sample-agent-egress")
	appendCheck("sample_agent.egress_policy_present", "sample-agent egress policy exists", policyFound)
	if policyFound {
		appendCheck("sample_agent.egress_only_nomos", "sample-agent can only egress to Nomos on TCP 8080", strings.Contains(agentPolicy, "app: nomos") && strings.Contains(agentPolicy, "port: 8080") && !strings.Contains(agentPolicy, "namespaceSelector: {}"))
	}

	nomosConfig, cfgFound := findManifestDoc(manifest, "kind: ConfigMap", "name: nomos-strong-config")
	appendCheck("nomos.config_present", "strong-guarantee config map exists", cfgFound)
	if cfgFound {
		appendCheck("nomos.strong_guarantee_enabled", "Nomos config enables strong guarantee mode", strings.Contains(nomosConfig, "\"strong_guarantee\": true"))
		appendCheck("nomos.controlled_runtime_mode", "Nomos config targets a controlled runtime deployment mode", strings.Contains(nomosConfig, "\"deployment_mode\": \"k8s\"") || strings.Contains(nomosConfig, "\"deployment_mode\": \"ci\""))
		appendCheck("nomos.container_sandbox", "Nomos config enforces container sandbox profile", strings.Contains(nomosConfig, "\"sandbox_profile\": \"container\""))
		appendCheck("nomos.durable_audit", "Nomos config uses a durable audit sink", strings.Contains(nomosConfig, "\"sink\": \"sqlite:") || strings.Contains(nomosConfig, "\"sink\": \"webhook:"))
		appendCheck("nomos.workload_identity", "Nomos config enables workload identity verification", strings.Contains(nomosConfig, "\"oidc\":") && strings.Contains(nomosConfig, "\"enabled\": true"))
		appendCheck("nomos.no_shared_api_keys", "Nomos strong-guarantee config avoids shared API keys", strings.Contains(nomosConfig, "\"api_keys\": {}"))
	}

	nomosDeployment, nomosFound := findManifestDoc(manifest, "kind: Deployment", "name: nomos")
	appendCheck("nomos.deployment_present", "nomos deployment exists", nomosFound)
	if nomosFound {
		appendCheck("nomos.run_as_non_root", "nomos runs as non-root", strings.Contains(nomosDeployment, "runAsNonRoot: true"))
		appendCheck("nomos.read_only_root_fs", "nomos uses readonly root filesystem", strings.Contains(nomosDeployment, "readOnlyRootFilesystem: true"))
		appendCheck("nomos.no_privilege_escalation", "nomos disables privilege escalation", strings.Contains(nomosDeployment, "allowPrivilegeEscalation: false"))
		appendCheck("nomos.no_host_path", "nomos avoids hostPath mounts", !strings.Contains(nomosDeployment, "hostPath:"))
	}

	return Report{Checks: checks}
}

func ValidateStrongGuaranteeCIWorkflow(workflow string) Report {
	checks := make([]Check, 0, 8)
	appendCheck := func(id, details string, ok bool) {
		checks = append(checks, Check{
			ID:      id,
			OK:      ok,
			Details: details,
		})
	}

	appendCheck("ci.workflow_present", "reference CI workflow exists", strings.TrimSpace(workflow) != "")
	appendCheck("ci.id_token_enabled", "CI workflow enables OIDC-style workload identity", strings.Contains(workflow, "id-token: write"))
	appendCheck("ci.strong_guarantee_env", "CI workflow declares strong guarantee mode", strings.Contains(workflow, "NOMOS_RUNTIME_STRONG_GUARANTEE: \"true\""))
	appendCheck("ci.controlled_runtime_mode", "CI workflow declares controlled runtime deployment mode", strings.Contains(workflow, "NOMOS_RUNTIME_DEPLOYMENT_MODE: \"ci\""))
	appendCheck("ci.no_shared_api_keys", "CI workflow does not inject shared API keys into the reference strong-guarantee config", !strings.Contains(workflow, "\"api_keys\": {") || strings.Contains(workflow, "\"api_keys\": {}"))
	appendCheck("ci.doctor_runs", "CI workflow runs nomos doctor", strings.Contains(workflow, "./bin/nomos doctor -c"))
	appendCheck("ci.doctor_json", "CI workflow validates deterministic doctor output", strings.Contains(workflow, "--format json"))
	appendCheck("ci.no_direct_agent_credentials", "CI workflow does not inject direct agent credentials into job env", !strings.Contains(workflow, "GITHUB_TOKEN:") && !strings.Contains(workflow, "OPENAI_API_KEY:") && !strings.Contains(workflow, "ANTHROPIC_API_KEY:"))

	return Report{Checks: checks}
}

func findManifestDoc(manifest string, required ...string) (string, bool) {
	for _, doc := range strings.Split(manifest, "---") {
		matches := true
		for _, pattern := range required {
			if !strings.Contains(doc, pattern) {
				matches = false
				break
			}
		}
		if matches {
			return doc, true
		}
	}
	return "", false
}
