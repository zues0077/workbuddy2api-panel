package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRootRedirectsToPanelWhenMounted(t *testing.T) {
	var mounted int
	h := NewHandler(Config{Panel: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mounted++
		w.WriteHeader(http.StatusAccepted)
	})})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("根路径状态码 = %d，想要 302", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/panel/" {
		t.Fatalf("Location = %q，想要 /panel/", got)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/panel/", nil))
	if mounted != 1 || rec.Code != http.StatusAccepted {
		t.Fatalf("/panel/ 转发坏了：命中 %d 次，状态码 %d", mounted, rec.Code)
	}
}

func TestRootStaysNotFoundWithoutPanel(t *testing.T) {
	rec := httptest.NewRecorder()
	NewHandler(Config{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("未挂面板时根路径 = %d，想要 404", rec.Code)
	}
}
