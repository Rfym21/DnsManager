package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/dns-manager/dnsmgr/server/internal/store"
)

func TestDeploymentResolutionRequiresAdminAndExactSubmission(t *testing.T) {
	a := testAPI(t)
	admin, token, csrf := testUser(t, a, "admin")
	_, restricted, restrictedCSRF := testUser(t, a, "restricted")
	ctx := context.Background()
	save := func(kind string, data any) store.Object {
		raw, _ := json.Marshal(data)
		object, err := a.Store.SaveObject(ctx, store.Object{Kind: kind, OwnerID: admin.ID, Name: "resolution fixture", Data: raw, Active: true}, true)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { a.Store.DB.Exec("DELETE FROM objects WHERE id=?", object.ID) })
		return object
	}
	certificate := save("certificates", map[string]any{"fingerprint": "generation-1", "status": "issued"})
	deployment := save("deployments", map[string]any{"certificate_id": certificate.ID, "deployed_fingerprint": "older-generation", "info": map[string]any{"certificate_id": "remote-9"}})
	makeUnknown := func() store.Job {
		job, err := a.Store.CreateJob(ctx, store.Job{Kind: "deployments", ResourceID: deployment.ID, OwnerID: admin.ID, Payload: []byte(`{"action":"execute"}`)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { a.Store.DB.Exec("DELETE FROM jobs WHERE id=?", job.ID) })
		marker := map[string]any{"job_id": job.ID, "fingerprint": "generation-1"}
		info := map[string]any{"certificate_id": "remote-9", "_dnsmgr_submit": marker}
		checkpoint, err := a.Store.Encrypt("job-checkpoint:"+job.ID, info)
		if err != nil {
			t.Fatal(err)
		}
		data := map[string]any{"certificate_id": certificate.ID, "deployed_fingerprint": "older-generation", "info": info}
		cipher, err := a.Store.Encrypt("object:"+deployment.ID, data)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = a.Store.DB.Exec("UPDATE objects SET data_ciphertext=? WHERE id=?", cipher, deployment.ID); err != nil {
			t.Fatal(err)
		}
		if _, err = a.Store.DB.Exec("UPDATE jobs SET state='unknown',checkpoint_ciphertext=? WHERE id=?", checkpoint, job.ID); err != nil {
			t.Fatal(err)
		}
		return job
	}
	job := makeUnknown()
	path := "/api/v1/jobs/" + job.ID + "/resolve"
	req := map[string]string{"resolution": "confirmed_success", "reason": "已在隔离平台逐一核对所有目标及证书指纹"}
	for _, test := range []struct {
		token, csrf string
		payload     any
		status      int
	}{{restricted, restrictedCSRF, req, 403}, {token, "", req, 403}, {token, csrf, map[string]string{"resolution": "confirmed_success", "reason": " "}, 400}} {
		response := requestAPI(a, "POST", path, test.token, test.csrf, test.payload)
		if response.Code != test.status {
			t.Fatal("resolution authorization/validation failed", response.Code, response.Body.String())
		}
	}
	locked, err := a.Store.LockResources(ctx, []string{"object:" + deployment.ID})
	if err != nil {
		t.Fatal(err)
	}
	response := requestAPI(a, "POST", path, token, csrf, req)
	locked()
	if response.Code != http.StatusConflict {
		t.Fatal("live deployment lock bypassed", response.Code)
	}
	response = requestAPI(a, "POST", path, token, csrf, req)
	if response.Code != 200 {
		t.Fatal(response.Code, response.Body.String())
	}
	current, err := a.Store.Job(ctx, job.ID)
	if err != nil || current.State != "succeeded" {
		t.Fatal("confirmed success did not finish job", current.State, err)
	}
	object, err := a.Store.Object(ctx, deployment.ID)
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]any
	json.Unmarshal(object.Data, &data)
	info := data["info"].(map[string]any)
	if data["deployed_fingerprint"] != "generation-1" || info["certificate_id"] != "remote-9" || info["_dnsmgr_submit"] != nil {
		t.Fatal("resolution did not preserve provider receipt or clear exact submit")
	}
	var audits, events int
	a.Store.DB.QueryRow("SELECT COUNT(*) FROM audit_events WHERE action='deployment.resolve' AND resource_id=?", job.ID).Scan(&audits)
	a.Store.DB.QueryRow("SELECT COUNT(*) FROM job_events WHERE job_id=? AND message='管理员已完成外部部署核对'", job.ID).Scan(&events)
	if audits != 1 || events != 1 {
		t.Fatal("resolution audit and job event were not committed together")
	}
	response = requestAPI(a, "POST", path, token, csrf, req)
	if response.Code != 409 {
		t.Fatal("completed resolution repeated", response.Code)
	}
	job = makeUnknown()
	path = "/api/v1/jobs/" + job.ID + "/resolve"
	req["resolution"] = "confirmed_no_write"
	req["reason"] = "外部平台确认所有目标未接收部署请求"
	response = requestAPI(a, "POST", path, token, csrf, req)
	if response.Code != 200 {
		t.Fatal(response.Code, response.Body.String())
	}
	current, _ = a.Store.Job(ctx, job.ID)
	object, _ = a.Store.Object(ctx, deployment.ID)
	json.Unmarshal(object.Data, &data)
	if current.State != "failed" || current.ErrorCode != "confirmed_no_write" || data["deployed_fingerprint"] != "older-generation" {
		t.Fatal("no-write resolution changed deployed generation", current.State, data["deployed_fingerprint"])
	}
	response = requestAPI(a, "POST", "/api/v1/jobs/"+job.ID+"/retry", token, csrf, nil)
	if response.Code != 202 {
		t.Fatal("confirmed no-write cannot retry", response.Code, response.Body.String())
	}
	a.Store.DB.Exec("UPDATE jobs SET state='failed' WHERE id=?", job.ID)
	job = makeUnknown()
	path = "/api/v1/jobs/" + job.ID + "/resolve"
	object, _ = a.Store.Object(ctx, deployment.ID)
	json.Unmarshal(object.Data, &data)
	data["info"].(map[string]any)["_dnsmgr_submit"] = map[string]string{"job_id": "different-job", "fingerprint": "generation-1"}
	cipher, _ := a.Store.Encrypt("object:"+deployment.ID, data)
	a.Store.DB.Exec("UPDATE objects SET data_ciphertext=? WHERE id=?", cipher, deployment.ID)
	response = requestAPI(a, "POST", path, token, csrf, req)
	if response.Code != 409 {
		t.Fatal("foreign job submission cleared", response.Code)
	}
	current, _ = a.Store.Job(ctx, job.ID)
	if current.State != "unknown" {
		t.Fatal("mismatch mutated job")
	}
	// A partial batch already contains durable success receipts. It cannot
	// be cleared as "no write" merely because an operator wants to retry.
	info = data["info"].(map[string]any)
	info["_dnsmgr_submit"] = map[string]string{"job_id": job.ID, "fingerprint": "generation-1"}
	info["results"] = []any{map[string]any{"target": "one", "success": true}}
	cipher, _ = a.Store.Encrypt("object:"+deployment.ID, data)
	a.Store.DB.Exec("UPDATE objects SET data_ciphertext=? WHERE id=?", cipher, deployment.ID)
	response = requestAPI(a, "POST", path, token, csrf, req)
	if response.Code != 409 {
		t.Fatal("partially completed batch declared no write", response.Code, response.Body.String())
	}
}

func TestDeploymentResolutionReasonRedactsActualSecrets(t *testing.T) {
	reason := redactResolutionSecrets("verified fixture-token and fixture-pass", map[string]any{"token": "fixture-token", "pfx_pass": "fixture-pass"})
	if reason != "verified [redacted] and [redacted]" {
		t.Fatal("resolution reason leaked credentials")
	}
	if !deploymentHasConfirmedSuccess(map[string]any{"info": map[string]any{"results": []any{map[string]any{"success": true}}}}) {
		t.Fatal("partial success receipt was ignored")
	}
}
