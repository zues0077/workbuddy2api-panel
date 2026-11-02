// types.go 本包内聚的渠道公共类型：错误分类、签到回执、积分明细、模型信息与定价。
//
// 与上游 sddvcm/workbuddy-api 的 internal/provider 对应，但本仓库没有渠道抽象层
// （面板以 realm 字符串 + 单一 upstream.Client 分发），故把 qodercn 用到的最小
// 类型集合直接放进本包，去掉对 provider 包的依赖。枚举值与上游逐一同名同序，
// 便于将来对照同步。
package qodercn

import (
	"fmt"
)

// ErrKind 错误分类，驱动面板 pool 冷却状态机（经 upstream 集成层映射到
// upstream.ErrKind，两边枚举同名同义）。
type ErrKind int

const (
	ErrNone          ErrKind = iota // 成功
	ErrHardCredit                   // 余额/权益不足 → 长冷却
	ErrSoftRate                     // 429 软限流 → 短冷却
	ErrSessionDead                  // 登录态失效 → 禁用
	ErrNotFound                     // 404 上游偶发 → 短冷却不累计 errCount
	ErrServer                       // 5xx 上游故障
	ErrClient                       // 其他 4xx / 业务错误
	ErrContentBlocked               // 内容策略拦截（400 + 审核文案）→ 不罚账号，透传原文
	ErrPromptTooLong                // 上下文超限 → 请求级错误，不罚号不轮转，透传原文
	ErrWafBlock                     // 403 + 非业务信封（WAF 拦截页/空体）→ 账号软冷却
	ErrAccountFault                 // 账号级授权/配额故障 → 冷却轮换
)

func (k ErrKind) String() string {
	switch k {
	case ErrHardCredit:
		return "hard_credit"
	case ErrSoftRate:
		return "soft_rate"
	case ErrSessionDead:
		return "session_dead"
	case ErrNotFound:
		return "not_found"
	case ErrServer:
		return "server"
	case ErrClient:
		return "client"
	case ErrContentBlocked:
		return "content_blocked"
	case ErrPromptTooLong:
		return "prompt_too_long"
	case ErrWafBlock:
		return "waf_block"
	case ErrAccountFault:
		return "account_fault"
	default:
		return "none"
	}
}

// Rotatable 报告该错误是否应换下一个账号重试本请求（账号级错误）。
func (k ErrKind) Rotatable() bool {
	switch k {
	case ErrSoftRate, ErrHardCredit, ErrSessionDead, ErrNotFound, ErrServer, ErrAccountFault, ErrClient:
		return true
	default:
		return false
	}
}

// Error 带分类的上游错误。
type Error struct {
	Kind   ErrKind
	Status int
	Msg    string
}

func (e *Error) Error() string {
	return fmt.Sprintf("upstream %s (http %d): %s", e.Kind, e.Status, e.Msg)
}

// CheckinStatus 签到结果状态（语义对齐上游 qoder2api 的 checkinStatus*）。
type CheckinStatus string

const (
	// CheckinClaimed 本次真正领取成功（金额可能为 0：上游未回填 benefit）。
	CheckinClaimed CheckinStatus = "claimed"
	// CheckinAlready 今日已领取（幂等：409 / CLAIMED / replayed）。
	CheckinAlready CheckinStatus = "already_claimed"
	// CheckinNoCampaign 无可用签到活动（含 legacy DISABLED）：可能是活动尚未创建，
	// 属于「可重试」状态——上游 10:00 整点存在延迟。
	CheckinNoCampaign CheckinStatus = "no_campaign"
	// CheckinNoToken 本地无可用凭据（可重试，refresh 后可能恢复）。
	CheckinNoToken CheckinStatus = "no_token"
	// CheckinError 其它失败（可重试）。
	CheckinError CheckinStatus = "error"
)

// Retryable 报告该状态是否应在当日窗口内继续重试。
func (s CheckinStatus) Retryable() bool {
	switch s {
	case CheckinClaimed, CheckinAlready:
		return false
	default:
		return true
	}
}

// CheckinReport 单次签到的结构化结果。
type CheckinReport struct {
	Status CheckinStatus
	Msg    string
	Amount int64
}

// ResourceItem 积分明细条目。
type ResourceItem struct {
	Name     string `json:"name"`
	Total    int64  `json:"total"`
	Used     int64  `json:"used"`
	Remain   int64  `json:"remain"`
	ExpireAt string `json:"expire_at,omitempty"`
	Key      string `json:"key,omitempty"`
	Usable   bool   `json:"usable"`
}

// ModelInfo 动态模型信息。
type ModelInfo struct {
	ID            string
	Name          string
	ContextWindow int64
	MaxTokens     int64
	// ContextFromAPI 标记 ContextWindow 是否来自上游接口（false = 硬编码估算）。
	ContextFromAPI   bool
	SupportsImages   bool
	SupportsReasoning bool
	SupportsTools    bool
}

// ModelPricing 模型积分定价。
type ModelPricing struct {
	Model   string  `json:"model"`
	Channel string  `json:"channel"`
	Rate    float64 `json:"rate"`
}
