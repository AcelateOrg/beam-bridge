package xray

import (
	"beam-bridge/core/types"

	applog "github.com/xtls/xray-core/app/log"
	corelog "github.com/xtls/xray-core/common/log"
	xcore "github.com/xtls/xray-core/core"
)

// coreLogSink подмешивает собственные логи ядра в буфер вкладки «Логи».
// Регистрируется после старта ядра и оборачивает хендлер app/log, который ядро
// ставит при разборе конфига, — так вывод в xray-core.log (в режиме
// разработчика) продолжает работать, а вкладка получает те же строки.
//
// Фильтрация по уровню: управляется пользовательской настройкой «Уровень
// логов» (error/info/debug). Режим разработчика пропускает всё.
type coreLogSink struct {
	inst *Instance
	next corelog.Handler
}

func (s coreLogSink) Handle(msg corelog.Message) {
	if s.next != nil {
		s.next.Handle(msg)
	}
	inst := s.inst
	if inst == nil || inst.logs == nil {
		return
	}
	// Тот же рубильник, что у записи логов ядра вообще: выключены — строка не
	// должна стоить вообще ничего.
	if !inst.logs.CoreLoggingEnabled() {
		return
	}
	general, ok := msg.(*corelog.GeneralMessage)
	if !ok {
		return
	}
	// Порог по уровню до любой работы со строками. Режим разработчика
	// пропускает всё безусловно.
	if !inst.ExtendedLogsEnabled() && severityRank(general.Severity) < inst.logs.MinRank() {
		return
	}
	text := sanitizeCoreMessage(general.String())
	if text == "" {
		return
	}
	inst.logs.Add(types.LogEntry{Level: coreLevelOf(text), Message: text})
}

func (i *Instance) installCoreLogSink(instance *xcore.Instance) {
	var next corelog.Handler
	if feature := instance.GetFeature((*applog.Instance)(nil)); feature != nil {
		if handler, ok := feature.(corelog.Handler); ok {
			next = handler
		}
	}
	corelog.RegisterHandler(coreLogSink{inst: i, next: next})
}

// severityRank переводит уровень ядра в ранг logLevelRank из logs.go:
// debug=1, info=2, warning=3, error=4 — то есть ту же шкалу, по которой
// LogBuffer фильтрует записи.
func severityRank(s corelog.Severity) int {
	switch s {
	case corelog.Severity_Debug:
		return logLevelRank[types.LogLevelDebug]
	case corelog.Severity_Info:
		return logLevelRank[types.LogLevelInfo]
	case corelog.Severity_Warning:
		return logLevelRank[types.LogLevelWarn]
	default:
		return logLevelRank[types.LogLevelError]
	}
}
