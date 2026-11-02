// qodercn_bridge.go Qoder 中国版渠道（realm "qodercn"）接入统一 upstream.Client 的桥接层。
//
// 设计：面板没有渠道抽象（见 repo AGENTS），所以 qodercn 不是平行 client，而是
// 在 Client 的既有入口按 realm 分流委托给内部 qodercn.Client。这样 handler 的
// 选号轮转、错误分类、粘性会话、预算记账、续写修复等全链路对 qodercn 账号原样
// 生效——唯一的新增是「嵌套 SSE → 标准 OpenAI SSE」的流式转写，让下游只认标准帧。
package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/misakano7545/workbuddy2api-panel/internal/auth"
	"github.com/misakano7545/workbuddy2api-panel/internal/logfmt"
	"github.com/misakano7545/workbuddy2api-panel/internal/qodercn"
)

// SetQoderCN 注入 qodercn 渠道委托。nil（缺省）= 渠道未装配：qodercn 账号的请求
// 会得到明确的「渠道未配置」错误而不是静默失败。
func (c *Client) SetQoderCN(q *qodercn.Client) { c.qcn = q }

// QoderCNEnabled 报告 qodercn 渠道是否已装配。
func (c *Client) QoderCNEnabled() bool { return c.qcn != nil }

// qcnChatStreamContext qodercn 账号的对话出站。
func (c *Client) qcnChatStreamContext(ctx context.Context, a *auth.Auth, body []byte) (rc io.ReadCloser, status int, respBody []byte, err error) {
	if c.qcn == nil {
		return nil, 0, nil, &Error{Kind: ErrClient, Msg: "qodercn channel not configured"}
	}
	// 出站 body 的 model 剥掉 "qodercn:"/"qodercn/" 网关前缀：上游只认裸名，
	// 与 WorkBuddy 的 normalizeModelName 同语义，但这里走自己的轻量版
	// （qodercn 不吃 efforts/maxOut/会话头那套 WorkBuddy 改写）。
	bare, prepared := qcnStripModelPrefix(body)
	rc, status, respBody, err = c.qcn.ChatStream(ctx, a, prepared)
	if err != nil {
		return nil, 0, nil, err
	}
	if status >= 400 {
		kind := qcnKind(c.qcn.Classify(status, string(respBody)))
		if kind == ErrNone {
			// 防御分支（≥400 不应产生 None）：返回原文让 handler 本地分类兜底。
			return nil, status, respBody, nil
		}
		return nil, status, respBody, &Error{Kind: kind, Status: status, Msg: string(respBody)}
	}
	// 嵌套 SSE → 标准 OpenAI SSE：转写 goroutine 持有上游 body 的所有权，
	// 读毕（或出错）负责 Close；pw.CloseWithError 把截断/读错误传给下游解析层。
	pr, pw := io.Pipe()
	go func() {
		_, terr := qodercn.Transcode(pw, rc, bare)
		rc.Close()
		pw.CloseWithError(terr)
	}()
	return pr, status, nil, nil
}

// qcnStripModelPrefix 剥出站 body model 的 qodercn 前缀，返回 (裸名, 改写后 body)。
// 无前缀时 body 原样返回。
func qcnStripModelPrefix(body []byte) (string, []byte) {
	var obj map[string]any
	if json.Unmarshal(body, &obj) != nil {
		return "", body
	}
	m, _ := obj["model"].(string)
	if i := strings.IndexAny(m, ":/"); i > 0 && m[:i] == auth.RealmQoderCN {
		m = m[i+1:]
		obj["model"] = m
		if nb, merr := json.Marshal(obj); merr == nil {
			return m, nb
		}
	}
	return m, body
}

// qcnKind qodercn.ErrKind → upstream.ErrKind（两边枚举同名同义，逐项映射，
// 不做数值转换——两边是独立 iota，序号无契约）。
func qcnKind(k qodercn.ErrKind) ErrKind {
	switch k {
	case qodercn.ErrHardCredit:
		return ErrHardCredit
	case qodercn.ErrSoftRate:
		return ErrSoftRate
	case qodercn.ErrSessionDead:
		return ErrSessionDead
	case qodercn.ErrNotFound:
		return ErrNotFound
	case qodercn.ErrServer:
		return ErrServer
	case qodercn.ErrClient:
		return ErrClient
	case qodercn.ErrContentBlocked:
		return ErrContentBlocked
	case qodercn.ErrPromptTooLong:
		return ErrPromptTooLong
	case qodercn.ErrWafBlock:
		return ErrWafBlock
	case qodercn.ErrAccountFault:
		return ErrAccountFault
	default:
		return ErrNone
	}
}

// qcnRequire 返回已装配的 qodercn 委托；未装配时报可读错误。
func (c *Client) qcnRequire() (*qodercn.Client, error) {
	if c.qcn == nil {
		return nil, fmt.Errorf("qodercn channel not configured")
	}
	return c.qcn, nil
}

// FetchQoderCNModels 拉取 qodercn 动态模型目录并转为面板 ModelInfo。
// a 为池内任一 qodercn 账号（签名请求需要 dt- token）。
func (c *Client) FetchQoderCNModels(a *auth.Auth) ([]ModelInfo, error) {
	q, err := c.qcnRequire()
	if err != nil {
		return nil, err
	}
	infos, err := q.FetchModels(a)
	if err != nil {
		return nil, err
	}
	out := make([]ModelInfo, 0, len(infos))
	for _, mi := range infos {
		out = append(out, ModelInfo{
			ID:                mi.ID,
			Name:              mi.Name,
			ContextWindow:     mi.ContextWindow,
			MaxTokens:         mi.MaxTokens,
			SupportsImages:    mi.SupportsImages,
			SupportsImagesSet: mi.SupportsImages, // is_vl 是上游显式声明
			SupportsReasoning: mi.SupportsReasoning,
			SupportsToolCall:  mi.SupportsTools,
		})
	}
	return out, nil
}

// FetchQoderCNUserInfo 拉取 qodercn /userinfo（登录流程回填 nickname/userType）。
func (c *Client) FetchQoderCNUserInfo(a *auth.Auth) (name, userType string, err error) {
	q, err := c.qcnRequire()
	if err != nil {
		return "", "", err
	}
	return q.FetchUserInfo(a)
}

// qcnRefreshToken qodercn 账号的 token 轮换（drt- → 新 dt-/drt-）。
// 返回 *Error（Kind 同 upstream 枚举），调用方的 errors.As 路径原样可用。
func (c *Client) qcnRefreshToken(a *auth.Auth) error {
	q, err := c.qcnRequire()
	if err != nil {
		return err
	}
	if err := q.RefreshToken(a); err != nil {
		var qe *qodercn.Error
		if errors.As(err, &qe) {
			return &Error{Kind: qcnKind(qe.Kind), Status: qe.Status, Msg: qe.Msg}
		}
		return err
	}
	log.Printf("INFO: [upstream] qodercn refresh ok uid=%s", logfmt.Label(a.UID, a.Nickname))
	return nil
}

// qcnUserResourceSnapshot qodercn 账号的余额快照（userQuota + addOnQuota 聚合）。
// qodercn 无到期批次概念：expiring/earliest 恒零值。
func (c *Client) qcnUserResourceSnapshot(a *auth.Auth) (remain, total int64, err error) {
	q, err := c.qcnRequire()
	if err != nil {
		return 0, 0, err
	}
	_, items, err := q.UserResourceDetail(a)
	if err != nil {
		return 0, 0, err
	}
	for _, it := range items {
		remain += it.Remain
		total += it.Total
	}
	return remain, total, nil
}

// qcnCheckin qodercn campaigns 签到（幂等：已领/无活动按可重试语义区分返回）。
func (c *Client) qcnCheckin(a *auth.Auth) error {
	q, err := c.qcnRequire()
	if err != nil {
		return err
	}
	rep, err := q.DailyCheckinReport(a)
	if err != nil {
		var qe *qodercn.Error
		if errors.As(err, &qe) {
			return &Error{Kind: qcnKind(qe.Kind), Status: qe.Status, Msg: qe.Msg}
		}
		return err
	}
	switch rep.Status {
	case qodercn.CheckinClaimed:
		log.Printf("INFO: [upstream] qodercn checkin %s: %s", logfmt.Label(a.UID, a.Nickname), rep.Msg)
		return nil
	case qodercn.CheckinAlready:
		// 文案含 already → IsAlreadyCheckin 命中，调度器按「今天已签到（幂等）」记账。
		return fmt.Errorf("already checked in today")
	case qodercn.CheckinNoCampaign:
		// 上游 10:00 整点可能尚未创建活动：返回可重试错误，下一轮 checkin 时点补签。
		return fmt.Errorf("no campaign yet (will retry at next checkin slot)")
	default:
		return fmt.Errorf("checkin %s: %s", rep.Status, rep.Msg)
	}
}
