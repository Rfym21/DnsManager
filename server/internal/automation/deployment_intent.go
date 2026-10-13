package automation

import (
	"context"
	"encoding/json"

	deployprovider "github.com/dns-manager/dnsmgr/server/internal/providers/deploy"
	"github.com/dns-manager/dnsmgr/server/internal/store"
)

const deploymentSubmitMarker = "_dnsmgr_submit"
const deploymentCompleteMarker = "_dnsmgr_complete"

func deploymentClearMarkers(info deployprovider.Info) deployprovider.Info {
	copy := deployprovider.Info{}
	for key, value := range info {
		if key != deploymentSubmitMarker && key != deploymentCompleteMarker {
			copy[key] = value
		}
	}
	return copy
}
func deploymentPendingInfo(info deployprovider.Info, jobID, fingerprint string) deployprovider.Info {
	copy := deploymentClearMarkers(info)
	copy[deploymentSubmitMarker] = map[string]string{"job_id": jobID, "fingerprint": fingerprint}
	return copy
}
func deploymentCompleteInfo(info deployprovider.Info, jobID, fingerprint string) deployprovider.Info {
	copy := deploymentClearMarkers(info)
	copy[deploymentCompleteMarker] = map[string]string{"job_id": jobID, "fingerprint": fingerprint}
	return copy
}
func deploymentSubmissionPending(info deployprovider.Info) bool {
	_, exists := info[deploymentSubmitMarker]
	return exists
}
func deploymentCompletedResult(info deployprovider.Info, jobID, fingerprint string) map[string]any {
	var marker struct {
		JobID       string `json:"job_id"`
		Fingerprint string `json:"fingerprint"`
	}
	raw, _ := json.Marshal(info[deploymentCompleteMarker])
	if json.Unmarshal(raw, &marker) != nil || marker.JobID != jobID || marker.Fingerprint != fingerprint {
		return nil
	}
	return map[string]any{"fingerprint": fingerprint, "info": safeLogData(deploymentClearMarkers(info))}
}
func (r *Runner) clearDeploymentSubmission(ctx context.Context, object store.Object, job store.Job, info deployprovider.Info) error {
	clean := deploymentClearMarkers(info)
	// Leave the job marker intact until the cross-job object marker is cleared.
	if _, err := r.Store.SaveObjectRuntime(ctx, object, job, map[string]any{"info": clean}, "", nil); err != nil {
		return err
	}
	return r.Store.CheckpointJob(ctx, job, clean)
}
