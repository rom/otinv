// Package templates holds the server-rendered views and their view models.
package templates

import "strings"

// Lang is a UI language tag.
type Lang string

// The languages the GUI ships with. English is the default.
const (
	LangEN Lang = "en"
	LangSV Lang = "sv"
)

// catalogue holds the UI strings. English is the fallback for anything a
// translation is missing, so an untranslated key degrades to English rather
// than to a blank label.
var catalogue = map[string]map[Lang]string{
	"nav.assets":                   {LangEN: "Assets", LangSV: "Tillgångar"},
	"nav.captures":                 {LangEN: "Captures", LangSV: "Infångningar"},
	"assets.title":                 {LangEN: "Assets", LangSV: "Tillgångar"},
	"assets.search":                {LangEN: "Search address or vendor", LangSV: "Sök adress eller tillverkare"},
	"assets.role":                  {LangEN: "Role", LangSV: "Roll"},
	"assets.protocol":              {LangEN: "Protocol", LangSV: "Protokoll"},
	"assets.all":                   {LangEN: "All", LangSV: "Alla"},
	"assets.filter":                {LangEN: "Filter", LangSV: "Filtrera"},
	"assets.address":               {LangEN: "Address", LangSV: "Adress"},
	"assets.vendor":                {LangEN: "Vendor", LangSV: "Tillverkare"},
	"assets.protocols":             {LangEN: "Protocols", LangSV: "Protokoll"},
	"assets.events":                {LangEN: "Events", LangSV: "Händelser"},
	"assets.seen":                  {LangEN: "Last seen", LangSV: "Senast sedd"},
	"assets.none":                  {LangEN: "No assets match this filter.", LangSV: "Inga tillgångar matchar filtret."},
	"assets.count":                 {LangEN: "matching assets", LangSV: "matchande tillgångar"},
	"assets.prev":                  {LangEN: "Previous", LangSV: "Föregående"},
	"assets.next":                  {LangEN: "Next", LangSV: "Nästa"},
	"asset.identity":               {LangEN: "Identity", LangSV: "Identitet"},
	"asset.addresses":              {LangEN: "Observed addresses", LangSV: "Observerade adresser"},
	"asset.evidence":               {LangEN: "Evidence", LangSV: "Bevis"},
	"asset.confidence":             {LangEN: "Confidence", LangSV: "Tillförlitlighet"},
	"asset.source":                 {LangEN: "Source", LangSV: "Källa"},
	"asset.field":                  {LangEN: "Field", LangSV: "Fält"},
	"asset.value":                  {LangEN: "Value", LangSV: "Värde"},
	"asset.role_reasons":           {LangEN: "Why this role", LangSV: "Varför denna roll"},
	"asset.recent_events":          {LangEN: "Recent events", LangSV: "Senaste händelser"},
	"asset.operation":              {LangEN: "Operation", LangSV: "Operation"},
	"asset.class":                  {LangEN: "Class", LangSV: "Klass"},
	"asset.packet":                 {LangEN: "Packet", LangSV: "Paket"},
	"asset.time":                   {LangEN: "Time", LangSV: "Tid"},
	"asset.peer":                   {LangEN: "Peer", LangSV: "Motpart"},
	"asset.unit":                   {LangEN: "Unit", LangSV: "Enhet"},
	"asset.side":                   {LangEN: "Side", LangSV: "Sida"},
	"asset.side.server":            {LangEN: "server", LangSV: "server"},
	"asset.side.client":            {LangEN: "client", LangSV: "klient"},
	"asset.gateway":                {LangEN: "Forwarding device", LangSV: "Vidarebefordrande enhet"},
	"captures.title":               {LangEN: "Captures", LangSV: "Infångningar"},
	"captures.file":                {LangEN: "File", LangSV: "Fil"},
	"captures.packets":             {LangEN: "Packets", LangSV: "Paket"},
	"captures.range":               {LangEN: "Time range", LangSV: "Tidsintervall"},
	"captures.none":                {LangEN: "No captures ingested yet.", LangSV: "Inga infångningar inlästa än."},
	"captures.digest":              {LangEN: "SHA-256", LangSV: "SHA-256"},
	"role.plc_rtu_ied":             {LangEN: "PLC / RTU / IED", LangSV: "PLC / RTU / IED"},
	"role.hmi_scada":               {LangEN: "HMI / SCADA", LangSV: "HMI / SCADA"},
	"role.engineering_workstation": {LangEN: "Engineering workstation", LangSV: "Ingenjörsarbetsstation"},
	"role.gateway":                 {LangEN: "Gateway", LangSV: "Gateway"},
	"role.unknown":                 {LangEN: "Unknown", LangSV: "Okänd"},
	"footer.passive":               {LangEN: "otinv reads captures only. It never sends packets.", LangSV: "otinv läser endast infångningar. Den skickar aldrig paket."},
}

// T returns the string for key in lang, falling back to English and then to
// the key itself, so a missing translation is visible but never empty.
func T(lang Lang, key string) string {
	entry, ok := catalogue[key]
	if !ok {
		return key
	}
	if s, ok := entry[lang]; ok && s != "" {
		return s
	}
	if s, ok := entry[LangEN]; ok {
		return s
	}
	return key
}

// ParseLang picks a UI language from an explicit choice or an Accept-Language
// header, defaulting to English.
func ParseLang(explicit, acceptLanguage string) Lang {
	if l := normaliseLang(explicit); l != "" {
		return l
	}
	for _, part := range strings.Split(acceptLanguage, ",") {
		tag, _, _ := strings.Cut(strings.TrimSpace(part), ";")
		if l := normaliseLang(tag); l != "" {
			return l
		}
	}
	return LangEN
}

func normaliseLang(tag string) Lang {
	tag = strings.ToLower(strings.TrimSpace(tag))
	base, _, _ := strings.Cut(tag, "-")
	switch Lang(base) {
	case LangSV:
		return LangSV
	case LangEN:
		return LangEN
	default:
		return ""
	}
}
