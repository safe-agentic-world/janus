package assurance

import (
	"testing"
)

func TestDeriveDeterministicForConfig(t *testing.T) {
	cases := []struct {
		name            string
		deploymentMode  string
		strongGuarantee bool
		evidence        Evidence
		expect          string
	}{
		{name: "k8s strong", deploymentMode: "k8s", strongGuarantee: true, evidence: Evidence{RuntimeIsolationVerified: true, WorkloadIdentityVerified: true, DurableAuditVerified: true}, expect: LevelStrong},
		{name: "k8s strong missing evidence degrades", deploymentMode: "k8s", strongGuarantee: true, evidence: Evidence{RuntimeIsolationVerified: false, WorkloadIdentityVerified: true, DurableAuditVerified: true}, expect: LevelGuarded},
		{name: "ci guarded", deploymentMode: "ci", strongGuarantee: false, expect: LevelGuarded},
		{name: "remote dev", deploymentMode: "remote_dev", expect: LevelBestEffort},
		{name: "unmanaged", deploymentMode: "unmanaged", expect: LevelBestEffort},
		{name: "unknown", deploymentMode: "unknown", expect: LevelNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got1 := DeriveWithEvidence(tc.deploymentMode, tc.strongGuarantee, tc.evidence)
			got2 := DeriveWithEvidence(tc.deploymentMode, tc.strongGuarantee, tc.evidence)
			if got1 != tc.expect || got2 != tc.expect {
				t.Fatalf("expected %s, got %s and %s", tc.expect, got1, got2)
			}
		})
	}
}
