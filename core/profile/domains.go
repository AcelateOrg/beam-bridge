package profile

import "strings"

type wildcardType int

const (
	wildcardExact wildcardType = iota
	wildcardSuffix
	wildcardKeyword
	wildcardPrefix
	wildcardComplex
)

type wildcardInfo struct {
	typ   wildcardType
	value string
}

func classifyDomains(domains []string) (exact, suffix, keyword, regex []string) {
	for _, domain := range domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}

		wildcard := analyzeWildcard(domain)
		switch wildcard.typ {
		case wildcardExact:
			if strings.HasPrefix(wildcard.value, ".") {
				suffix = append(suffix, wildcard.value)
				continue
			}
			exact = append(exact, wildcard.value)
			suffix = append(suffix, "."+wildcard.value)
		case wildcardSuffix:
			suffix = append(suffix, dotPrefixed(wildcard.value))
		case wildcardKeyword:
			keyword = append(keyword, wildcard.value)
		case wildcardPrefix, wildcardComplex:
			regex = append(regex, wildcardToRegex(domain))
		}
	}
	return
}

func dotPrefixed(value string) string {
	if strings.HasPrefix(value, ".") {
		return value
	}
	return "." + value
}

func sanitizeWildcard(pattern string) string {
	for strings.Contains(pattern, "**") {
		pattern = strings.ReplaceAll(pattern, "**", "*")
	}
	return pattern
}

func analyzeWildcard(pattern string) wildcardInfo {
	pattern = sanitizeWildcard(pattern)

	if !strings.Contains(pattern, "*") {
		return wildcardInfo{typ: wildcardExact, value: pattern}
	}
	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
		if keyword := strings.Trim(pattern, "*"); keyword != "" && !strings.Contains(keyword, "*") {
			return wildcardInfo{typ: wildcardKeyword, value: keyword}
		}
	}
	if strings.HasPrefix(pattern, "*.") {
		if suffix := strings.TrimPrefix(pattern, "*."); suffix != "" && !strings.Contains(suffix, "*") {
			return wildcardInfo{typ: wildcardSuffix, value: suffix}
		}
	}
	if strings.HasSuffix(pattern, ".*") {
		if prefix := strings.TrimSuffix(pattern, ".*"); prefix != "" && !strings.Contains(prefix, "*") {
			return wildcardInfo{typ: wildcardPrefix, value: prefix}
		}
	}
	return wildcardInfo{typ: wildcardComplex, value: pattern}
}

func wildcardToRegex(pattern string) string {
	pattern = sanitizeWildcard(pattern)

	var builder strings.Builder
	builder.WriteString("^")
	for i, part := range strings.Split(pattern, "*") {
		if i > 0 {
			builder.WriteString(".*")
		}
		if part != "" {
			builder.WriteString(regexEscape(part))
		}
	}
	builder.WriteString("$")
	return builder.String()
}

func regexEscape(value string) string {
	const special = `\.+?^${}()|[]`

	var builder strings.Builder
	for _, char := range value {
		if strings.ContainsRune(special, char) {
			builder.WriteRune('\\')
		}
		builder.WriteRune(char)
	}
	return builder.String()
}
