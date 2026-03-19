package assurance

import "strings"

const (
	LevelStrong     = "STRONG"
	LevelGuarded    = "GUARDED"
	LevelBestEffort = "BEST_EFFORT"
	LevelNone       = "NONE"
)

type Evidence struct {
	RuntimeIsolationVerified bool
	WorkloadIdentityVerified bool
	DurableAuditVerified     bool
}

func NormalizeDeploymentMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "ci":
		return "ci"
	case "k8s":
		return "k8s"
	case "remote_dev":
		return "remote_dev"
	case "unmanaged":
		return "unmanaged"
	default:
		return ""
	}
}

func Derive(deploymentMode string, strongGuarantee bool) string {
	return DeriveWithEvidence(deploymentMode, strongGuarantee, Evidence{
		RuntimeIsolationVerified: strongGuarantee,
		WorkloadIdentityVerified: strongGuarantee,
		DurableAuditVerified:     strongGuarantee,
	})
}

func DeriveWithEvidence(deploymentMode string, strongGuarantee bool, evidence Evidence) string {
	mode := NormalizeDeploymentMode(deploymentMode)
	switch mode {
	case "ci", "k8s":
		if strongGuarantee {
			if evidence.RuntimeIsolationVerified && evidence.WorkloadIdentityVerified && evidence.DurableAuditVerified {
				return LevelStrong
			}
			return LevelGuarded
		}
		return LevelGuarded
	case "remote_dev", "unmanaged":
		return LevelBestEffort
	default:
		return LevelNone
	}
}
