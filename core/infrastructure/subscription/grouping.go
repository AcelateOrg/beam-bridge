package subscription

import (
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Per-host Beam params. A panel adds them to the share link query
// (Remnawave: host -> Mapper -> Base64, op "set"); other clients ignore
// unknown params, so the link keeps working everywhere.
const (
	paramGroup     = "beam-group"
	paramDesc      = "beam-desc"
	paramBadge     = "beam-badge"
	paramSeparator = "beam-separator"
	paramCollapsed = "beam-collapsed"
)

const (
	maxGroupName   = 40
	maxDescription = 60
	maxBadge       = 16
)

type linkExtras struct {
	group       string
	description string
	badge       string
	separator   bool
	collapsed   bool
}

func parseLinkExtras(line string) linkExtras {
	var ex linkExtras
	q := strings.IndexByte(line, '?')
	if q < 0 {
		return ex
	}
	query := line[q+1:]
	if h := strings.IndexByte(query, '#'); h >= 0 {
		query = query[:h]
	}
	if !strings.Contains(query, "beam-") {
		return ex
	}
	values, _ := url.ParseQuery(query)
	group := values.Get(paramGroup)
	// Mapper "copy $host.metadata.tags" arrives as "tag1,tag2".
	if i := strings.IndexByte(group, ','); i >= 0 {
		group = group[:i]
	}
	ex.group = cleanText(group, maxGroupName)
	ex.description = cleanText(maybeBase64Text(values.Get(paramDesc)), maxDescription)
	ex.badge = cleanText(values.Get(paramBadge), maxBadge)
	ex.separator = parseBoolMeta(values.Get(paramSeparator))
	ex.collapsed = parseBoolMeta(values.Get(paramCollapsed))
	return ex
}

// splitServerDescription cuts the "?serverDescription=..." Remnawave and
// Happ append after the remark (base64 or plain text).
func splitServerDescription(line string) (string, string) {
	hash := strings.LastIndexByte(line, '#')
	if hash < 0 {
		return line, ""
	}
	const marker = "?serverDescription="
	idx := strings.Index(line[hash:], marker)
	if idx < 0 {
		return line, ""
	}
	idx += hash
	raw := strings.TrimSpace(line[idx+len(marker):])
	line = line[:idx]
	if decoded, err := decodeBase64(raw); err == nil && len(decoded) > 0 && utf8.Valid(decoded) {
		raw = string(decoded)
	} else if unescaped, err := url.PathUnescape(raw); err == nil {
		raw = maybeBase64Text(unescaped)
	}
	return line, cleanText(raw, maxDescription)
}

var base64Text = regexp.MustCompile(`^[A-Za-z0-9+/_-]{8,}={0,2}$`)

// maybeBase64Text unwraps text the panel keeps in base64 (Remnawave's
// serverDescription copied by the mapper). Plain words stay untouched:
// only a clean base64 token that decodes to printable UTF-8 is unwrapped.
func maybeBase64Text(s string) string {
	s = strings.TrimSpace(s)
	if rest, ok := strings.CutPrefix(s, "base64:"); ok {
		if decoded, err := decodeBase64(rest); err == nil && utf8.Valid(decoded) {
			return string(decoded)
		}
		return s
	}
	if len(s)%4 != 0 || !base64Text.MatchString(s) {
		return s
	}
	decoded, err := decodeBase64(s)
	if err != nil || !utf8.Valid(decoded) {
		return s
	}
	for _, r := range string(decoded) {
		if !unicode.IsPrint(r) {
			return s
		}
	}
	return string(decoded)
}

func cleanText(s string, limit int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) > limit {
		s = string([]rune(s)[:limit])
	}
	return strings.TrimSpace(s)
}

func readableName(name string) string {
	if unescaped, err := url.PathUnescape(name); err == nil {
		return unescaped
	}
	return name
}

const arrowChars = `⬇⬆↓↑⤵⤴👇👆🔽🔼▼▲`

var (
	// "⬇️ —— ДОМАШНИЕ —— ⬇️", "━━ Игровые ━━", "== VIP =="
	dashedSeparator = regexp.MustCompile(`^[^\p{L}\p{N}]*[-=_~─━═—–·•]{2,}.*[\p{L}\p{N}].*[-=_~─━═—–·•]{2,}[^\p{L}\p{N}]*$`)
	// "[Игровые]", "【VIP】"
	bracketSeparator = regexp.MustCompile(`^\s*(\[[^\[\]]+\]|【[^【】]+】)\s*$`)
	// "⬇️ Домашние ⬇️"
	arrowSeparator = regexp.MustCompile(`^\s*[` + arrowChars + `]\x{FE0F}?.*[\p{L}\p{N}].*[` + arrowChars + `]\x{FE0F}?\s*$`)
	// "———————" with no text at all: pure decoration.
	bareDivider = regexp.MustCompile(`^[^\p{L}\p{N}]*[-=_~─━═—–·•]{3,}[^\p{L}\p{N}]*$`)

	edgeJunk = regexp.MustCompile(`^[^\p{L}\p{N}(]+|[^\p{L}\p{N})!?]+$`)
)

// isSeparatorName reports a fake "server" whose only job is to head a group.
func isSeparatorName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	return dashedSeparator.MatchString(name) ||
		bracketSeparator.MatchString(name) ||
		arrowSeparator.MatchString(name) ||
		bareDivider.MatchString(name)
}

// prettyCategoryName: "⬇️ —— ДОМАШНИЕ —— ⬇️" -> "Домашние".
func prettyCategoryName(label string) string {
	name := edgeJunk.ReplaceAllString(strings.TrimSpace(label), "")
	name = strings.Trim(name, " -=_~─━═—–·•[]【】")
	name = cleanText(name, maxGroupName)
	return sentenceCase(name)
}

// sentenceCase turns a shouted "ДОМАШНИЕ СЕРВЕРЫ" into "Домашние серверы";
// short acronyms (VIP, EU) and mixed case stay as they are.
func sentenceCase(s string) string {
	letters := 0
	for _, r := range s {
		if unicode.IsLower(r) {
			return s
		}
		if unicode.IsLetter(r) {
			letters++
		}
	}
	if letters < 4 {
		return s
	}
	runes := []rune(strings.ToLower(s))
	for i, r := range runes {
		if unicode.IsLetter(r) {
			runes[i] = unicode.ToUpper(r)
			break
		}
	}
	return string(runes)
}

// categoryEmoji picks the provider's icon out of a separator: the first
// emoji that is not an arrow ("🎮 —— Игровые ——" -> "🎮", flags included).
func categoryEmoji(label string) string {
	runes := []rune(label)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if strings.ContainsRune(arrowChars, r) || !isEmojiBase(r) {
			continue
		}
		if isRegionalIndicator(r) {
			if i+1 < len(runes) && isRegionalIndicator(runes[i+1]) {
				return string(runes[i : i+2])
			}
			continue
		}
		end := i + 1
		for end < len(runes) {
			next := runes[end]
			switch {
			case next == 0xFE0F || (next >= 0x1F3FB && next <= 0x1F3FF):
				end++
			case next == 0x200D && end+1 < len(runes):
				end += 2
			default:
				return string(runes[i:end])
			}
		}
		return string(runes[i:end])
	}
	return ""
}

func isRegionalIndicator(r rune) bool {
	return r >= 0x1F1E6 && r <= 0x1F1FF
}

// isEmojiBase accepts real pictographs only. Box drawing, geometric
// shapes, arrows and math dingbats (➖ ➡ ▬) are separator decoration and
// would make a dash-looking group icon.
func isEmojiBase(r rune) bool {
	switch {
	case isRegionalIndicator(r):
		return true
	case r >= 0x1F300 && r <= 0x1FAFF: // pictographs, emoticons, symbols
		return true
	case r >= 0x2600 && r <= 0x26FF: // ☀ ⚡ ⚽ ⭐-like misc symbols
		return true
	case r >= 0x2700 && r <= 0x2793: // dingbats up to the arrows block
		return r != 0x2795 && r != 0x2796 && r != 0x2797 && unicode.Is(unicode.So, r)
	case r == 0x2B50 || r == 0x2B55 || r == 0x231A || r == 0x231B || (r >= 0x23E9 && r <= 0x23FA):
		return true
	}
	return false
}
