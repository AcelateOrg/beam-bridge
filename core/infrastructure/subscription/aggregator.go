package subscription

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"beam-bridge/core/infrastructure/beam"
	"beam-bridge/core/infrastructure/subscription/parsers"
	"beam-bridge/core/types"
)

type Aggregator struct {
	parser  *parsers.ParserRegistry
	client  *http.Client
	fetcher *Fetcher
}

func NewAggregator(client *http.Client) *Aggregator {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &Aggregator{
		parser:  parsers.NewRegistry(),
		client:  client,
		fetcher: NewFetcher(client),
	}
}

func (a *Aggregator) Parser() *parsers.ParserRegistry {
	return a.parser
}

func (a *Aggregator) Fetcher() *Fetcher {
	return a.fetcher
}

type ParseResult struct {
	Categories []types.Category
	Nodes      []types.BeamNode
	Meta       *SubscriptionMeta
}

func (a *Aggregator) ParseSubscription(data []byte) (*ParseResult, error) {
	content := string(data)

	trimmed := strings.TrimSpace(content)
	hasHeader := strings.HasPrefix(trimmed, "#")

	if !hasHeader {
		if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil {
			content = string(decoded)
		} else if decoded, err := base64.RawStdEncoding.DecodeString(trimmed); err == nil {
			content = string(decoded)
		}
		hasHeader = strings.HasPrefix(strings.TrimSpace(content), "#")
	}

	lines := strings.Split(strings.TrimSpace(content), "\n")

	var meta *SubscriptionMeta
	if hasHeader {
		meta = ParseSubscriptionMeta(lines)
	}

	result := &ParseResult{
		Categories: []types.Category{{ID: "default", Name: "Серверы", Order: 0}},
		Nodes:      []types.BeamNode{},
		Meta:       meta,
	}

	currentCategoryID := "default"
	categoryIndex := 0
	nodeIndex := 0

	// One category per name: a separator and a beam-group param with the
	// same name land in the same group.
	categoryByName := map[string]int{}
	addCategory := func(label string, collapsed bool) string {
		name := prettyCategoryName(label)
		if name == "" {
			name = "Серверы"
		}
		key := strings.ToLower(name)
		if i, ok := categoryByName[key]; ok {
			if collapsed {
				result.Categories[i].Collapsed = true
			}
			return result.Categories[i].ID
		}
		categoryIndex++
		cat := types.Category{
			ID:        fmt.Sprintf("cat_%d", categoryIndex),
			Name:      name,
			Icon:      detectCategoryIcon(name),
			Emoji:     categoryEmoji(label),
			Order:     categoryIndex,
			Collapsed: collapsed,
		}
		categoryByName[key] = len(result.Categories)
		result.Categories = append(result.Categories, cat)
		return cat.ID
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if IsMetaLine(line) {
			continue
		}

		if strings.HasPrefix(line, "#") {
			continue
		}

		if IsCategoryMarker(line, a.parser) {
			currentCategoryID = addCategory(line, false)
			continue
		}

		var serverDesc string
		line, serverDesc = splitServerDescription(line)

		outbound, err := a.parser.Parse(line)
		if err == nil && outbound != nil {
			extras := parseLinkExtras(line)
			nodeName := extractNodeName(outbound)

			// Panels fake group headers with dummy servers named
			// "⬇️ —— ДОМАШНИЕ —— ⬇️": turn them into real categories.
			if label := readableName(nodeName); extras.separator || isSeparatorName(label) {
				if prettyCategoryName(label) != "" {
					currentCategoryID = addCategory(label, extras.collapsed)
				}
				continue
			}

			categoryID := currentCategoryID
			if extras.group != "" {
				categoryID = addCategory(extras.group, extras.collapsed)
			}
			description := extras.description
			if description == "" {
				description = serverDesc
			}

			nodeIndex++
			nodeID := fmt.Sprintf("node_%d", nodeIndex)
			nodeType, _ := outbound["type"].(string)
			result.Nodes = append(result.Nodes, types.BeamNode{
				ID:          nodeID,
				CategoryID:  categoryID,
				Name:        nodeName,
				Type:        nodeType,
				Outbound:    outbound,
				RawLink:     line,
				Description: description,
				Badge:       extras.badge,
			})
		}
	}

	if len(result.Categories) > 1 {
		hasDefaultNodes := false
		for _, node := range result.Nodes {
			if node.CategoryID == "default" {
				hasDefaultNodes = true
				break
			}
		}
		if !hasDefaultNodes {
			result.Categories = result.Categories[1:]
		}
	}

	if len(result.Nodes) == 0 {
		return nil, errors.New("no valid nodes found")
	}

	return result, nil
}

// tryParseHostedBeam распознаёт подписку, отдающую готовый .beam-файл.
// Зашифрованные (v3) намеренно не поддерживаем: пароль внутри подписки
// бессмысленнен. URL подписки подставляем, если в файле его нет; учёт
// трафика и интервал обновления дотягиваем из HTTP-заголовков, если файл
// их не задаёт.
func tryParseHostedBeam(data []byte, rawURL string, header http.Header) (*beam.BeamFile, bool) {
	// Leading space only: the gzip trailer is binary and may end in bytes
	// that look like whitespace.
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	isBeam := len(trimmed) >= len(beam.BeamMagic) && bytes.Equal(trimmed[:len(beam.BeamMagic)], beam.BeamMagic)
	// The same gzipped JSON a beam:// link carries, served as is.
	isGzip := len(trimmed) >= 2 && trimmed[0] == 0x1f && trimmed[1] == 0x8b
	if !isBeam && !isGzip {
		return nil, false
	}
	beamFile, err := beam.ParseData(trimmed)
	if err != nil || beamFile == nil || (len(beamFile.Data.Nodes) == 0 && len(beamFile.Data.Links) == 0) {
		return nil, false
	}
	if beamFile.Data.URL == "" {
		beamFile.Data.URL = rawURL
	}
	if beamFile.Data.Provider == "" {
		beamFile.Data.Provider = extractProvider(rawURL)
	}
	if subInfo := parseSubscriptionInfo(header); subInfo != nil {
		if subInfo.Expire > 0 {
			beamFile.Data.ExpiresAt = subInfo.Expire
		}
		if subInfo.Total > 0 {
			beamFile.Data.DataLimit = subInfo.Total
		}
		beamFile.Data.DataUsed = subInfo.Upload + subInfo.Download
	}
	applyHeaderBranding(&beamFile.Data, header)
	if beamFile.Data.UpdateIntervalHours <= 0 {
		beamFile.Data.UpdateIntervalHours = resolveUpdateIntervalHours(header, nil)
	}
	return beamFile, true
}

// brandingFromMeta собирает блок брендинга из мета-заголовков подписки.
func brandingFromMeta(meta *SubscriptionMeta) *types.Branding {
	if meta == nil {
		return nil
	}
	b := &types.Branding{
		IconURL:      meta.IconURL,
		BannerText:   meta.Announce,
		BannerURL:    meta.BannerURL,
		BannerColor:  meta.BannerColor,
		BannerImage:  meta.BannerImage,
		WebPageURL:   meta.WebPageURL,
		SupportURL:   meta.SupportURL,
		CommunityURL: meta.CommunityURL,
	}
	if b.Empty() {
		return nil
	}
	return b
}

func (a *Aggregator) BuildBeamFromSubscription(data []byte, rawURL string, header http.Header) (*beam.BeamFile, error) {
	beamFile, meta, err := a.buildBeamFromSubscription(data, rawURL, header)
	if err != nil {
		return nil, err
	}
	applyDisplayHeaders(&beamFile.Data, header)
	applyProTunHeader(&beamFile.Data, header, meta)
	if beamFile.Data.ProviderSettings == nil {
		beamFile.Data.ProviderSettings = providerSettings(header, meta, rawURL)
	}
	return beamFile, nil
}

func (a *Aggregator) buildBeamFromSubscription(data []byte, rawURL string, header http.Header) (*beam.BeamFile, *SubscriptionMeta, error) {
	// Провайдер может хостить готовый .beam — тогда берём его целиком:
	// брендинг, ProTun-пресет и лок приезжают из файла, а из HTTP-заголовков
	// дотягиваем только учёт трафика и интервал обновления.
	if beamFile, ok := tryParseHostedBeam(data, rawURL, header); ok {
		if err := a.ExpandLinks(beamFile); err != nil {
			return nil, nil, err
		}
		return beamFile, nil, nil
	}

	if trimmed := strings.TrimSpace(string(data)); looksLikeXrayConfigArray(trimmed) {
		if xrayResult, xrayErr := parseXrayConfigArray(data); xrayErr == nil {
			name := extractName(header, rawURL)
			beamFile := beam.New(name, extractProvider(rawURL), rawURL)
			beamFile.Data.Categories = xrayResult.Categories
			beamFile.Data.Nodes = xrayResult.Nodes

			if subInfo := parseSubscriptionInfo(header); subInfo != nil {
				if subInfo.Expire > 0 {
					beamFile.Data.ExpiresAt = subInfo.Expire
				}
				if subInfo.Total > 0 {
					beamFile.Data.DataLimit = subInfo.Total
				}
				beamFile.Data.DataUsed = subInfo.Upload + subInfo.Download
			}
			applyHeaderBranding(&beamFile.Data, header)
			beamFile.Data.UpdateIntervalHours = resolveUpdateIntervalHours(header, nil)

			return beamFile, nil, nil
		}
	}

	result, err := a.ParseSubscription(data)
	if err == nil {
		result.Meta = withHeaderMeta(result.Meta, header)
		name := ""
		if result.Meta != nil && result.Meta.Title != "" {
			name = result.Meta.Title
		}
		if name == "" {
			name = extractName(header, rawURL)
		}

		beamFile := beam.New(name, extractProvider(rawURL), rawURL)
		beamFile.Data.Categories = result.Categories
		beamFile.Data.Nodes = result.Nodes

		httpSubInfo := parseSubscriptionInfo(header)
		if httpSubInfo != nil {
			if httpSubInfo.Expire > 0 {
				beamFile.Data.ExpiresAt = httpSubInfo.Expire
			}
			if httpSubInfo.Total > 0 {
				beamFile.Data.DataLimit = httpSubInfo.Total
			}
			beamFile.Data.DataUsed = httpSubInfo.Upload + httpSubInfo.Download
		} else if result.Meta != nil {
			if result.Meta.Expire > 0 {
				beamFile.Data.ExpiresAt = result.Meta.Expire
			}
			if result.Meta.Total > 0 {
				beamFile.Data.DataLimit = result.Meta.Total
			}
			beamFile.Data.DataUsed = result.Meta.Upload + result.Meta.Download
		}

		beamFile.Data.MergeBrandingFrom(brandingFromHeader(header))
		if result.Meta != nil {
			if result.Meta.Announce != "" {
				beamFile.Data.Announce = result.Meta.Announce
			}
			if result.Meta.SupportURL != "" {
				beamFile.Data.SupportURL = result.Meta.SupportURL
			}
			if result.Meta.IconURL != "" {
				beamFile.Data.IconURL = result.Meta.IconURL
			}
			if result.Meta.CommunityURL != "" {
				beamFile.Data.CommunityURL = result.Meta.CommunityURL
			}
			beamFile.Data.MergeBrandingFrom(brandingFromMeta(result.Meta))
		}
		beamFile.Data.UpdateIntervalHours = resolveUpdateIntervalHours(header, result.Meta)

		return beamFile, result.Meta, nil
	}

	var config map[string]interface{}
	if jsonErr := json.Unmarshal(data, &config); jsonErr != nil {
		return nil, nil, ErrInvalidConfig
	}

	outboundsRaw, ok := config["outbounds"].([]interface{})
	if !ok || len(outboundsRaw) == 0 {
		return nil, nil, ErrInvalidConfig
	}

	name := extractName(header, rawURL)
	beamFile := beam.New(name, extractProvider(rawURL), rawURL)
	beamFile.Data.Categories = append(beamFile.Data.Categories, types.Category{
		ID: "default", Name: "Серверы", Order: 0,
	})

	for i, obMap := range SingBoxProxies(outboundsRaw) {
		beamFile.AddNode(generateNodeID(i+1), "default", str(obMap, "tag"), str(obMap, "type"), obMap)
	}

	if len(beamFile.Data.Nodes) == 0 {
		return nil, nil, ErrInvalidConfig
	}

	subInfo := parseSubscriptionInfo(header)
	if subInfo != nil {
		if subInfo.Expire > 0 {
			beamFile.Data.ExpiresAt = subInfo.Expire
		}
		if subInfo.Total > 0 {
			beamFile.Data.DataLimit = subInfo.Total
		}
		beamFile.Data.DataUsed = subInfo.Upload + subInfo.Download
	}
	applyHeaderBranding(&beamFile.Data, header)
	beamFile.Data.UpdateIntervalHours = resolveUpdateIntervalHours(header, nil)

	return beamFile, nil, nil
}

func resolveUpdateIntervalHours(header http.Header, meta *SubscriptionMeta) int {
	if v := strings.TrimSpace(header.Get("Profile-Update-Interval")); v != "" {
		if hours, err := strconv.Atoi(v); err == nil && hours > 0 {
			return hours
		}
	}
	if meta != nil && meta.UpdateInterval > 0 {
		return meta.UpdateInterval
	}
	return 0
}

func generateNodeID(index int) string {
	return fmt.Sprintf("node_%d", index)
}

func extractProvider(rawURL string) string {
	parsed, _ := url.Parse(rawURL)
	if parsed != nil && parsed.Host != "" {
		return parsed.Host
	}
	return "Custom"
}

func parseSubscriptionInfo(header http.Header) *types.SubscriptionInfo {
	userinfo := header.Get("Subscription-Userinfo")
	if userinfo == "" {
		return nil
	}
	info := &types.SubscriptionInfo{}
	parts := strings.Split(userinfo, ";")
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		value, _ := strconv.ParseInt(strings.TrimSpace(kv[1]), 10, 64)
		switch key {
		case "upload":
			info.Upload = value
		case "download":
			info.Download = value
		case "total":
			info.Total = value
		case "expire":
			info.Expire = normalizeExpire(value)
		}
	}
	return info
}

func decodeNameIfNeeded(name string) string {
	if strings.HasPrefix(name, "base64:") {
		encodedStr := strings.TrimPrefix(name, "base64:")
		if decoded, err := decodeBase64(encodedStr); err == nil && len(decoded) > 0 {
			return string(decoded)
		}
	}
	return name
}

func extractName(header http.Header, rawURL string) string {
	// Profile-Title is what the panel admin set; Content-Disposition is
	// usually just the username (Remnawave), so it only goes second.
	title := strings.TrimSpace(header.Get("Profile-Title"))
	if title == "" {
		title = strings.TrimSpace(header.Get("Subscription-Name"))
	}
	if title != "" {
		title = strings.TrimPrefix(title, "base64:")
		if decoded, err := decodeBase64(title); err == nil && len(decoded) > 0 {
			return decodeNameIfNeeded(string(decoded))
		}
		return decodeNameIfNeeded(title)
	}
	if disp := header.Get("Content-Disposition"); disp != "" {
		if strings.Contains(disp, "filename=") {
			parts := strings.Split(disp, "filename=")
			if len(parts) > 1 {
				name := strings.Trim(parts[1], `"' `)
				if name != "" {
					return decodeNameIfNeeded(name)
				}
			}
		}
	}
	parsed, _ := url.Parse(rawURL)
	if parsed != nil && parsed.Host != "" {
		return decodeNameIfNeeded(parsed.Host)
	}
	return "Subscription"
}

func IsCategoryMarker(line string, parser *parsers.ParserRegistry) bool {
	if parser.IsProtocolLink(line) {
		return false
	}
	if IsMetaLine(line) {
		return false
	}

	patterns := []string{
		`^[💫✨🌟⭐🔥🎮🎯🚀💎👑🏆]+.*[💫✨🌟⭐🔥🎮🎯🚀💎👑🏆]+$`,
		`^[-=─━═]+\s*.+\s*[-=─━═]+$`,
		`^\[.+\]$`,
		`^#\s*.+$`,
		`^【.+】$`,
	}
	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, line); matched {
			return true
		}
	}

	outbound, err := parser.Parse(line)
	if err == nil && outbound != nil {
		server, _ := outbound["server"].(string)
		if server == "127.0.0.1" || server == "0.0.0.0" || server == "localhost" {
			return true
		}
	}
	return false
}

func extractCategoryName(line string) string {
	emojiPattern := regexp.MustCompile(`^[\p{So}\p{Sk}\s]+|[\p{So}\p{Sk}\s]+$`)
	name := emojiPattern.ReplaceAllString(line, "")
	separatorPattern := regexp.MustCompile(`^[-=─━═\[\]【】#\s]+|[-=─━═\[\]【】\s]+$`)
	name = separatorPattern.ReplaceAllString(name, "")
	name = strings.TrimSpace(name)
	if name == "" {
		return "Серверы"
	}
	return name
}

func detectCategoryIcon(name string) string {
	lower := strings.ToLower(name)
	iconMap := map[string]string{
		"gaming":  "Gamepad2",
		"game":    "Gamepad2",
		"игр":     "Gamepad2",
		"stream":  "Play",
		"video":   "Play",
		"видео":   "Play",
		"fast":    "Zap",
		"быстр":   "Zap",
		"скорост": "Zap",
		"premium": "Crown",
		"премиум": "Crown",
		"vip":     "Crown",
		"обход":   "Shield",
		"bypass":  "Shield",
		"secure":  "Lock",
		"безопас": "Lock",
	}
	for keyword, icon := range iconMap {
		if strings.Contains(lower, keyword) {
			return icon
		}
	}
	return "Folder"
}

func extractNodeName(outbound map[string]interface{}) string {
	if tag, ok := outbound["tag"].(string); ok && tag != "" {
		return tag
	}
	if server, ok := outbound["server"].(string); ok {
		return server
	}
	return "Unknown"
}

func isServiceOutbound(obType string) bool {
	serviceTypes := map[string]bool{
		"selector": true,
		"direct":   true,
		"block":    true,
		"dns":      true,
		"urltest":  true,
	}
	return serviceTypes[obType]
}

func decodeBase64(s string) ([]byte, error) {
	if decoded, err := base64.StdEncoding.DecodeString(s); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.URLEncoding.DecodeString(s); err == nil {
		return decoded, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}
