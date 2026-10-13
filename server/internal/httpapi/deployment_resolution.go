package httpapi

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/dns-manager/dnsmgr/server/internal/redaction"
	"github.com/go-chi/chi/v5/middleware"
)

type deploymentResolutionRequest struct {
	Resolution string `json:"resolution"`
	Reason     string `json:"reason"`
}
type deploymentSubmissionMarker struct {
	JobID       string `json:"job_id"`
	Fingerprint string `json:"fingerprint"`
}

func deploymentMarker(info map[string]any) (deploymentSubmissionMarker, bool) {
	var marker deploymentSubmissionMarker
	raw, _ := json.Marshal(info["_dnsmgr_submit"])
	if json.Unmarshal(raw, &marker) != nil || marker.JobID == "" || marker.Fingerprint == "" {
		return marker, false
	}
	return marker, true
}

// Resolve records an administrator's external verification; it performs no
// provider requests and only clears the submission belonging to this exact job.
func (a *API) resolveDeploymentJob(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	var req deploymentResolutionRequest
	if !a.decode(w, r, &req) {
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if (req.Resolution != "confirmed_success" && req.Resolution != "confirmed_no_write") || req.Reason == "" || utf8.RuneCountInString(req.Reason) > 1000 || strings.Contains(req.Reason, "-----BEGIN") {
		a.fail(w, r, 400, "invalid_resolution", "请选择核对结果并填写外部核查依据，理由最多1000字且不得包含证书或私钥")
		return
	}
	j, release, ok := a.recoveryJob(w, r)
	if !ok {
		return
	}
	defer release()
	if j.Kind != "deployments" || (j.State != "unknown" && j.State != "partial") || j.ResourceID == "" {
		a.fail(w, r, 409, "not_resolvable", "仅结果未知或部分完成的部署任务支持人工核对")
		return
	}
	tx, err := a.Store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	defer tx.Rollback()
	var objectCipher, kind string
	if err = tx.QueryRowContext(r.Context(), "SELECT kind,data_ciphertext FROM objects WHERE id=? FOR UPDATE", j.ResourceID).Scan(&kind, &objectCipher); err != nil {
		a.internal(w, r, err)
		return
	}
	if kind != "deployments" {
		a.fail(w, r, 409, "not_resolvable", "任务对应的部署资源已改变")
		return
	}
	var data map[string]any
	if err = a.Store.Decrypt("object:"+j.ResourceID, objectCipher, &data); err != nil {
		a.internal(w, r, err)
		return
	}
	info, _ := data["info"].(map[string]any)
	if info == nil {
		info = map[string]any{}
	}
	var checkpointCipher sql.NullString
	var resultCipher sql.NullString
	var currentState string
	if err = tx.QueryRowContext(r.Context(), "SELECT state,checkpoint_ciphertext,result_ciphertext FROM jobs WHERE id=? FOR UPDATE", j.ID).Scan(&currentState, &checkpointCipher, &resultCipher); err != nil {
		a.internal(w, r, err)
		return
	}
	if currentState != "unknown" && currentState != "partial" {
		a.fail(w, r, 409, "not_resolvable", "任务状态已改变")
		return
	}
	checkpoint := map[string]any{}
	if checkpointCipher.Valid {
		if err = a.Store.Decrypt("job-checkpoint:"+j.ID, checkpointCipher.String, &checkpoint); err != nil {
			a.internal(w, r, err)
			return
		}
	}
	marker, hasMarker := deploymentMarker(info)
	jobMarker, hasJobMarker := deploymentMarker(checkpoint)
	if !hasMarker && hasJobMarker {
		marker, hasMarker = jobMarker, true
	}
	if !hasMarker || marker.JobID != j.ID || (hasJobMarker && jobMarker != marker) {
		a.fail(w, r, 409, "submission_mismatch", "部署提交标记与此任务不匹配，请保留现场并核对原始任务")
		return
	}
	certificateID, _ := data["certificate_id"].(string)
	var certificateCipher string
	if err = tx.QueryRowContext(r.Context(), "SELECT data_ciphertext FROM objects WHERE id=? AND kind='certificates' FOR UPDATE", certificateID).Scan(&certificateCipher); err != nil {
		a.internal(w, r, err)
		return
	}
	var certificate struct {
		Fingerprint string `json:"fingerprint"`
	}
	if err = a.Store.Decrypt("object:"+certificateID, certificateCipher, &certificate); err != nil {
		a.internal(w, r, err)
		return
	}
	if certificate.Fingerprint != marker.Fingerprint {
		a.fail(w, r, 409, "submission_mismatch", "证书代次已改变，不能把旧提交核对结果应用于新证书")
		return
	}
	if req.Resolution == "confirmed_no_write" {
		result := map[string]any{}
		if resultCipher.Valid {
			if err = a.Store.Decrypt("job-result:"+j.ID, resultCipher.String, &result); err != nil {
				a.internal(w, r, err)
				return
			}
		}
		if deploymentHasConfirmedSuccess(result) || deploymentHasConfirmedSuccess(info) || deploymentHasConfirmedSuccess(checkpoint) {
			a.fail(w, r, 409, "partial_write_confirmed", "任务已经确认部分目标部署成功，不能声明未发生写入；请核对并完成所有目标后确认成功")
			return
		}
	}
	// A free-form audit reason can accidentally repeat a credential. Scrub
	// actual account/target secrets and certificate material before any storage.
	var certSecrets struct {
		Fullchain  string `json:"fullchain"`
		PrivateKey string `json:"private_key"`
	}
	if err = a.Store.Decrypt("object:"+certificateID, certificateCipher, &certSecrets); err != nil {
		a.internal(w, r, err)
		return
	}
	req.Reason = redactResolutionValue(req.Reason, certSecrets.Fullchain)
	req.Reason = redactResolutionValue(req.Reason, certSecrets.PrivateKey)
	for _, key := range []string{"target", "config"} {
		if values, ok := data[key].(map[string]any); ok {
			req.Reason = redactResolutionSecrets(req.Reason, values)
		}
	}
	if accountID, _ := data["account_id"].(string); accountID != "" {
		var accountCipher string
		if err = tx.QueryRowContext(r.Context(), "SELECT data_ciphertext FROM objects WHERE id=? AND kind='deploy_accounts'", accountID).Scan(&accountCipher); err != nil {
			a.internal(w, r, err)
			return
		}
		var account struct {
			Config map[string]any `json:"config"`
		}
		if err = a.Store.Decrypt("object:"+accountID, accountCipher, &account); err != nil {
			a.internal(w, r, err)
			return
		}
		req.Reason = redactResolutionSecrets(req.Reason, account.Config)
	}
	delete(info, "_dnsmgr_submit")
	delete(info, "_dnsmgr_complete")
	delete(checkpoint, "_dnsmgr_submit")
	delete(checkpoint, "_dnsmgr_complete")
	state := "failed"
	now := time.Now().UTC()
	if req.Resolution == "confirmed_success" {
		state = "succeeded"
		data["deployed_fingerprint"] = marker.Fingerprint
		data["last_run"] = now
	}
	resolution := map[string]any{"resolution": req.Resolution, "reason": req.Reason, "actor_id": principal(r).User.ID, "job_id": j.ID, "fingerprint": marker.Fingerprint, "resolved_at": now}
	data["info"] = info
	data["last_resolution"] = resolution
	objectCipher, err = a.Store.Encrypt("object:"+j.ResourceID, data)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	checkpointEnc, err := a.Store.Encrypt("job-checkpoint:"+j.ID, checkpoint)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	resultEnc, err := a.Store.Encrypt("job-result:"+j.ID, map[string]any{"resolution": resolution, "fingerprint": marker.Fingerprint})
	if err != nil {
		a.internal(w, r, err)
		return
	}
	if _, err = tx.ExecContext(r.Context(), "UPDATE objects SET data_ciphertext=?,version=version+1,updated_at=UTC_TIMESTAMP(6) WHERE id=?", objectCipher, j.ResourceID); err != nil {
		a.internal(w, r, err)
		return
	}
	errorCode, errorMessage := "", ""
	if state == "failed" {
		errorCode = "confirmed_no_write"
		errorMessage = "管理员已核对外部平台，确认未执行部署，可重试"
	}
	if _, err = tx.ExecContext(r.Context(), "UPDATE jobs SET state=?,checkpoint_ciphertext=?,result_ciphertext=?,error_code=?,error_message=?,cancel_requested=FALSE,completed=IF(?='succeeded',total,completed),lease_owner=NULL,lease_until=NULL,updated_at=UTC_TIMESTAMP(6) WHERE id=? AND state IN ('unknown','partial')", state, checkpointEnc, resultEnc, errorCode, errorMessage, state, j.ID); err != nil {
		a.internal(w, r, err)
		return
	}
	auditRaw, _ := json.Marshal(resolution)
	var domain any
	if j.DomainID != "" {
		domain = j.DomainID
	}
	if _, err = tx.ExecContext(r.Context(), "INSERT INTO audit_events(actor_id,action,resource_type,resource_id,domain_id,request_id,detail,created_at) VALUES(?,?,?,?,?,?,?,UTC_TIMESTAMP(6))", principal(r).User.ID, "deployment.resolve", "job", j.ID, domain, middleware.GetReqID(r.Context()), redaction.JSON(auditRaw)); err != nil {
		a.internal(w, r, err)
		return
	}
	if _, err = tx.ExecContext(r.Context(), "INSERT INTO job_events(job_id,level,message,data,created_at) VALUES(?,'info','管理员已完成外部部署核对',?,UTC_TIMESTAMP(6))", j.ID, redaction.JSON(auditRaw)); err != nil {
		a.internal(w, r, err)
		return
	}
	if err = tx.Commit(); err != nil {
		a.internal(w, r, err)
		return
	}
	j, err = a.Store.Job(r.Context(), j.ID)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	j.Result = redactJSON(j.Result)
	send(w, 200, map[string]any{"job": j})
}

func deploymentHasConfirmedSuccess(value any) bool {
	switch item := value.(type) {
	case map[string]any:
		if success, ok := item["success"].(bool); ok && success {
			return true
		}
		for _, child := range item {
			if deploymentHasConfirmedSuccess(child) {
				return true
			}
		}
	case []any:
		for _, child := range item {
			if deploymentHasConfirmedSuccess(child) {
				return true
			}
		}
	}
	return false
}
func redactResolutionSecrets(reason string, values map[string]any) string {
	for key, value := range values {
		name := strings.ToLower(key)
		if redaction.Key(key) || name == "pass" || strings.HasSuffix(name, "_pass") {
			if secret, ok := value.(string); ok {
				reason = redactResolutionValue(reason, secret)
			}
		}
	}
	return reason
}
func redactResolutionValue(reason, value string) string {
	if value != "" {
		reason = strings.ReplaceAll(reason, value, "[redacted]")
		encoded, _ := json.Marshal(value)
		if len(encoded) > 2 {
			reason = strings.ReplaceAll(reason, string(encoded[1:len(encoded)-1]), "[redacted]")
		}
	}
	return reason
}
