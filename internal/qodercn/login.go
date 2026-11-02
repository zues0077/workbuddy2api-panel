// login.go QoderCN OAuth 设备授权（PKCE Device Flow）。
//
// 代码级移植自 sddvcm/workbuddy-api internal/login_qodercn（其又复制自 qoder2api
// 参数形态）：授权 URL 仅带 nonce/challenge/challenge_method/client_id，不带
// redirect_uri——纯轮询式设备流，页面授权完成后由调用方轮询 deviceToken/poll 拿凭据。
// 登录成功后凭据由调用方落盘；userType/nickname 用 FetchUserInfo 补齐（设备流响应里无）。
package qodercn

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	// OAuthWebsiteCN 授权页站点；OAuthOpenapiCN 轮询端点站点。
	OAuthWebsiteCN = "https://qoder.com.cn"
	OAuthOpenapiCN = "https://openapi.qoder.com.cn"
	// OAuthClientID qoder2api CN/Global 共用的 OAuth 客户端 ID。
	OAuthClientID = "e883ade2-e6e3-4d6d-adf7-f92ceff5fdcb"
	// loginUA 设备流端点的 UA（qoder2api 形态）。
	loginUA = "Go-http-client/2.0"
)

// ErrLoginPending 表示授权尚未完成（poll 404/202）。
var ErrLoginPending = errors.New("login pending")

// LoginResult 登录成功后拿到的凭据与账号标识。
type LoginResult struct {
	AccessToken  string // dt-
	RefreshToken string // drt-
	ExpiresIn    int64  // 秒
	UID          string
}

// NewLoginChallenge 生成 PKCE 三元组：verifier（落会话，poll 时用）、nonce、授权 URL。
func NewLoginChallenge() (verifier, nonce, authURL string) {
	verifier, challenge := makePKCE()
	nonce = newSimpleID()
	authURL = fmt.Sprintf("%s/device/selectAccounts?nonce=%s&challenge=%s&challenge_method=S256&client_id=%s",
		OAuthWebsiteCN, nonce, challenge, OAuthClientID)
	return verifier, nonce, authURL
}

// PollDeviceToken 单次轮询设备令牌；未完成返回 ErrLoginPending；成功返回 dt-/drt-。
// qoder2api 语义：404=尚未授权继续等；202 同义；其余 >=400 视为失败。
func PollDeviceToken(client *http.Client, nonce, verifier string) (LoginResult, error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	url := fmt.Sprintf("%s/api/v1/deviceToken/poll?nonce=%s&verifier=%s&challenge_method=S256",
		OAuthOpenapiCN, nonce, verifier)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return LoginResult{}, err
	}
	req.Header.Set("User-Agent", loginUA)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return LoginResult{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusAccepted {
		return LoginResult{}, ErrLoginPending
	}
	if resp.StatusCode >= 400 {
		return LoginResult{}, fmt.Errorf("http %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	var tok map[string]any
	if err := json.Unmarshal(raw, &tok); err != nil {
		return LoginResult{}, fmt.Errorf("parse: %w", err)
	}
	t := loginStr(tok, "token")
	if t == "" {
		t = loginStr(tok, "device_token")
	}
	if t == "" {
		return LoginResult{}, ErrLoginPending
	}
	uid := loginStr(tok, "user_id")
	if uid == "" {
		uid = loginStr(tok, "uid")
	}
	return LoginResult{
		AccessToken:  t,
		RefreshToken: loginStr(tok, "refresh_token"),
		ExpiresIn:    int64(loginFloat(tok, "expires_in")),
		UID:          uid,
	}, nil
}

// makePKCE verifier + S256 challenge（qoder2api pkce() 形态：64 字节采样）。
func makePKCE() (verifier, challenge string) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	buf := make([]byte, 64)
	_, _ = rand.Read(buf)
	var sb strings.Builder
	sb.Grow(64)
	for _, b := range buf {
		sb.WriteByte(alphabet[int(b)%len(alphabet)])
	}
	verifier = sb.String()
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return
}

// newSimpleID qoder2api 的会话标识形态（毫秒时间戳 + 随机 hex）。
func newSimpleID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%d%x", time.Now().UnixNano()/1e6, b)
}

func loginStr(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

func loginFloat(m map[string]any, key string) float64 {
	if m == nil {
		return 0
	}
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return n
	case json.Number:
		if f, err := n.Float64(); err == nil {
			return f
		}
	}
	return 0
}
