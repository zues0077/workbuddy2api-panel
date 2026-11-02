// login_qodercn.go 面板内嵌的 QoderCN OAuth 设备授权（PKCE Device Flow），
// 与 login.go 的 WorkBuddy 设备流并列的第三渠道入口：
//
//	POST /panel/api/qodercn/login/start → 生成 PKCE 会话，返回授权 URL；
//	GET  /panel/api/qodercn/login/poll?state=… → 前端每 3s 轮询；未完成 done=false，
//	  完成后凭据落盘 auths/qodercn-<uid>.json（realm=qodercn + 机器指纹）、热加载进池
//	  （Add + Revive），并回查余额 —— 免重启加载新账号。
//
// PKCE 原语与轮询端点在 internal/qodercn/login.go；面板只管会话状态与落盘。
package panel

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"github.com/misakano7545/workbuddy2api-panel/internal/auth"
	"github.com/misakano7545/workbuddy2api-panel/internal/qodercn"
)

// qcnLoginState 进行中的 qodercn 设备授权会话（与 loginSession 平行，字段独立：
// PKCE verifier/nonce 是本渠道特有状态，混进通用会话表会让两条流程互相理解成本升高）。
type qcnLoginState struct {
	created  time.Time
	verifier string
	nonce    string
	// processing 该 state 正在落盘（余额回查可能耗时数秒，而前端 3s 一轮；
	// 没有闸门第二个并发 poll 会把整段流程再跑一遍）。
	processing bool
	lastMsg    string
}

// qodercnLoginStart 发起设备授权：生成 PKCE 会话并返回授权 URL。
func (p *Panel) qodercnLoginStart(w http.ResponseWriter, r *http.Request) {
	verifier, nonce, authURL := qodercn.NewLoginChallenge()
	state, err := newStateID()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "gen state: "+err.Error())
		return
	}
	p.qcnMu.Lock()
	// 顺手回收过期会话，防「开弹窗走开」的 state 滞留。
	for s, sess := range p.qcnLogins {
		if time.Since(sess.created) > loginTTL {
			delete(p.qcnLogins, s)
		}
	}
	p.qcnLogins[state] = qcnLoginState{created: time.Now(), verifier: verifier, nonce: nonce}
	p.qcnMu.Unlock()
	log.Printf("panel: 发起 QoderCN 设备授权（state=%s...）", state[:min(8, len(state))])
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "url": authURL, "state": state, "realm": auth.RealmQoderCN})
}

// qodercnLoginPoll 轮询设备令牌。未完成 → {done:false}；完成 → 落盘、热加载、回余额。
func (p *Panel) qodercnLoginPoll(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if state == "" {
		writeErr(w, http.StatusBadRequest, "missing state")
		return
	}
	p.qcnMu.Lock()
	sess, known := p.qcnLogins[state]
	if known && sess.processing {
		p.qcnMu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"done": false, "message": "正在写入凭据…"})
		return
	}
	if known {
		sess.processing = true
		p.qcnLogins[state] = sess
	}
	p.qcnMu.Unlock()
	if !known {
		// 410：会话已过期/进程重启。前端据此停止轮询（与 WorkBuddy 流程同语义）。
		writeErr(w, http.StatusGone, "login session 已过期，请关闭后重新添加账号")
		return
	}
	// 失败路径复位闸门（成功路径 delete(state) 已清掉）。
	defer func() {
		p.qcnMu.Lock()
		if s, ok := p.qcnLogins[state]; ok {
			s.processing = false
			p.qcnLogins[state] = s
		}
		p.qcnMu.Unlock()
	}()

	res, err := qodercn.PollDeviceToken(loginHTTP, sess.nonce, sess.verifier)
	if err != nil {
		if errors.Is(err, qodercn.ErrLoginPending) {
			p.qcnLogPollOnce(state, "pending")
			writeJSON(w, http.StatusOK, map[string]any{"done": false, "message": "等待浏览器侧完成授权…"})
			return
		}
		p.qcnLogPollOnce(state, err.Error())
		writeJSON(w, http.StatusOK, map[string]any{"done": false, "message": err.Error()})
		return
	}
	// UID 拼文件名前的防路径穿越校验（与 WorkBuddy 流程同一判据）。
	if !validUID(res.UID) {
		p.qcnMu.Lock()
		delete(p.qcnLogins, state)
		p.qcnMu.Unlock()
		writeErr(w, http.StatusBadGateway, "上游返回的 uid 缺失或含非法字符，拒绝落盘（防路径穿越）")
		return
	}
	p.qcnMu.Lock()
	delete(p.qcnLogins, state)
	p.qcnMu.Unlock()

	a := &auth.Auth{
		AccessToken:  res.AccessToken,
		RefreshToken: res.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(res.ExpiresIn) * time.Second).Unix(),
		Domain:       "qoder.com.cn",
		UID:          res.UID,
		FilePath:     filepath.Join(p.cfg.AuthDir, fmt.Sprintf("qodercn-%s.json", res.UID)),
	}
	// realm 显式落盘（不依赖 domain 推断），机器指纹补齐后再原子写入。
	if _, err := auth.BackfillRealmFor(a, auth.RealmQoderCN); err != nil {
		writeErr(w, http.StatusInternalServerError, "set realm: "+err.Error())
		return
	}
	qodercn.EnsureFingerprint(a)
	if err := a.SaveAtomic(); err != nil {
		writeErr(w, http.StatusInternalServerError, "save auth: "+err.Error())
		return
	}
	// 昵称回填（设备流响应无 nickname）：失败不影响登录结果。
	if name, _, uerr := p.cfg.Upstream.FetchQoderCNUserInfo(a); uerr == nil && name != "" {
		// Pool.Add 之前独占持有该 Auth，直接赋值无并发风险。
		a.Nickname = name
		if serr := a.SaveAtomicRetry(); serr != nil {
			log.Printf("panel: qodercn 昵称回写失败 uid=%s: %v", res.UID, serr)
		}
	} else if uerr != nil {
		log.Printf("panel: qodercn userinfo uid=%s: %v", res.UID, uerr)
	}

	isNewAccount := p.cfg.Pool.AuthByUID(res.UID) == nil
	p.cfg.Pool.Add(a)
	p.cfg.Pool.Revive(res.UID)

	// 余额回查（幂等；失败不影响登录结果，只体现在返回字段里）。
	// 不顺带签到：campaigns 活动要 10:00 后才由上游创建，新登录多半 no_campaign，
	// 交给排程的 checkin_times 补跑（qcnCheckin 对 no_campaign 返回可重试错误）。
	balanceMsg := ""
	remain := int64(-1)
	total := int64(0)
	if rm, tt, berr := p.cfg.Upstream.UserResource(a); berr == nil {
		remain, total = rm, tt
		p.cfg.Pool.ReenableIfCredits(res.UID, rm, tt)
	} else {
		balanceMsg = berr.Error()
		log.Printf("panel: qodercn 登录后余额校验失败 uid=%s: %v", res.UID, berr)
	}
	if isNewAccount {
		p.StartNewAccountTasks(res.UID)
	}
	log.Printf("panel: QoderCN 账号已热加载 uid=%s（免重启生效）", res.UID)
	writeJSON(w, http.StatusOK, map[string]any{
		"done":          true,
		"uid":           res.UID,
		"nickname":      a.Nickname,
		"realm":         auth.RealmQoderCN,
		"credits":       remain,
		"credits_total": total,
		"balance_error": balanceMsg,
	})
}

// qcnLogPollOnce 上游轮询结果变了才落一行日志（与 logPollOnce 同理：3s 一轮的
// 轮询会把一次性错误刷没，只在结果变化时记）。
func (p *Panel) qcnLogPollOnce(state, msg string) {
	p.qcnMu.Lock()
	s, ok := p.qcnLogins[state]
	if !ok || s.lastMsg == msg {
		p.qcnMu.Unlock()
		return
	}
	s.lastMsg = msg
	p.qcnLogins[state] = s
	p.qcnMu.Unlock()
	log.Printf("panel: QoderCN 登录轮询 state=%s... 上游=%s", state[:min(8, len(state))], msg)
}

// newStateID 生成 URL 安全的会话标识（16 字节 hex，与上游 state 无关——本渠道
// 的防 CSRF 由 PKCE challenge 承担，state 只是面板自己的会话键）。
func newStateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "qcn" + hex.EncodeToString(b), nil
}
