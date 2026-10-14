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
	"nav.dashboard":                {LangEN: "Dashboard", LangSV: "Översikt"},
	"nav.flows":                    {LangEN: "Flows", LangSV: "Flöden"},
	"nav.matrix":                   {LangEN: "Matrix", LangSV: "Matris"},
	"nav.events":                   {LangEN: "Events", LangSV: "Händelser"},
	"nav.protocols":                {LangEN: "Protocols", LangSV: "Protokoll"},
	"nav.settings":                 {LangEN: "Settings", LangSV: "Inställningar"},
	"dashboard.title":              {LangEN: "Dashboard", LangSV: "Översikt"},
	"dashboard.recent":             {LangEN: "Latest events", LangSV: "Senaste händelser"},
	"dashboard.no_events":          {LangEN: "No events ingested yet.", LangSV: "Inga händelser inlästa än."},
	"dashboard.all_events":         {LangEN: "All events", LangSV: "Alla händelser"},
	"dashboard.charts_off":         {LangEN: "Charts are switched off in the settings.", LangSV: "Diagram är avstängda i inställningarna."},
	"tile.assets":                  {LangEN: "Assets", LangSV: "Tillgångar"},
	"tile.controllers":             {LangEN: "controllers", LangSV: "styrsystem"},
	"tile.events":                  {LangEN: "Events", LangSV: "Händelser"},
	"tile.protocols":               {LangEN: "Protocols", LangSV: "Protokoll"},
	"tile.flows":                   {LangEN: "flows", LangSV: "flöden"},
	"tile.captures":                {LangEN: "Captures", LangSV: "Infångningar"},
	"tile.malformed":               {LangEN: "Malformed frames", LangSV: "Felaktiga ramar"},
	"tile.anomalies":               {LangEN: "Anomalies", LangSV: "Avvikelser"},
	"tile.exceptions":              {LangEN: "Protocol errors", LangSV: "Protokollfel"},
	"tile.span":                    {LangEN: "Time covered", LangSV: "Tidsomfång"},
	"tile.packets":                 {LangEN: "packets", LangSV: "paket"},
	"tile.gateways":                {LangEN: "forwarding devices", LangSV: "vidarebefordrande enheter"},
	"tile.none":                    {LangEN: "none", LangSV: "inga"},
	"flows.title":                  {LangEN: "Flows", LangSV: "Flöden"},
	"flows.source":                 {LangEN: "Source", LangSV: "Källa"},
	"flows.destination":            {LangEN: "Destination", LangSV: "Mål"},
	"flows.protocol":               {LangEN: "Protocol", LangSV: "Protokoll"},
	"flows.events":                 {LangEN: "Events", LangSV: "Händelser"},
	"flows.mix":                    {LangEN: "Operation mix", LangSV: "Operationsfördelning"},
	"flows.first":                  {LangEN: "First seen", LangSV: "Först sedd"},
	"flows.last":                   {LangEN: "Last seen", LangSV: "Senast sedd"},
	"flows.count":                  {LangEN: "matching flows", LangSV: "matchande flöden"},
	"flows.none":                   {LangEN: "No flows match this filter.", LangSV: "Inga flöden matchar filtret."},
	"flows.search":                 {LangEN: "Search endpoint or protocol", LangSV: "Sök ändpunkt eller protokoll"},
	"flows.malformed":              {LangEN: "malformed", LangSV: "felaktiga"},
	"matrix.title":                 {LangEN: "Communication matrix", LangSV: "Kommunikationsmatris"},
	"matrix.corner":                {LangEN: "from ╲ to", LangSV: "från ╲ till"},
	"matrix.none":                  {LangEN: "No traffic matches this filter.", LangSV: "Ingen trafik matchar filtret."},
	"matrix.truncated":             {LangEN: "Only the busiest endpoints are shown.", LangSV: "Endast de mest aktiva ändpunkterna visas."},
	"matrix.size":                  {LangEN: "Endpoints", LangSV: "Ändpunkter"},
	"matrix.help":                  {LangEN: "A row talks, a column listens. The darker the square, the more operations; click one for the events behind it.", LangSV: "En rad talar, en kolumn lyssnar. Desto mörkare ruta, desto fler operationer; klicka på en för händelserna bakom den."},
	"events.title":                 {LangEN: "Events", LangSV: "Händelser"},
	"events.time":                  {LangEN: "Time", LangSV: "Tid"},
	"events.protocol":              {LangEN: "Protocol", LangSV: "Protokoll"},
	"events.operation":             {LangEN: "Operation", LangSV: "Operation"},
	"events.class":                 {LangEN: "Class", LangSV: "Klass"},
	"events.source":                {LangEN: "Source", LangSV: "Källa"},
	"events.destination":           {LangEN: "Destination", LangSV: "Mål"},
	"events.packet":                {LangEN: "Packet", LangSV: "Paket"},
	"events.count":                 {LangEN: "matching events", LangSV: "matchande händelser"},
	"events.none":                  {LangEN: "No events match this filter.", LangSV: "Inga händelser matchar filtret."},
	"events.search":                {LangEN: "Search operation, error or address", LangSV: "Sök operation, fel eller adress"},
	"events.only_malformed":        {LangEN: "Malformed only", LangSV: "Endast felaktiga"},
	"events.only_anomalous":        {LangEN: "Anomalies only", LangSV: "Endast avvikelser"},
	"events.clear":                 {LangEN: "Clear filters", LangSV: "Rensa filter"},
	"protocols.title":              {LangEN: "Protocols", LangSV: "Protokoll"},
	"protocols.protocol":           {LangEN: "Protocol", LangSV: "Protokoll"},
	"protocols.events":             {LangEN: "Events", LangSV: "Händelser"},
	"protocols.flows":              {LangEN: "Flows", LangSV: "Flöden"},
	"protocols.mix":                {LangEN: "Operation mix", LangSV: "Operationsfördelning"},
	"protocols.health":             {LangEN: "Parse health", LangSV: "Avkodningshälsa"},
	"protocols.range":              {LangEN: "First seen", LangSV: "Först sedd"},
	"protocols.none":               {LangEN: "No protocols decoded yet.", LangSV: "Inga protokoll avkodade än."},
	"protocols.malformed":          {LangEN: "malformed", LangSV: "felaktiga"},
	"protocols.anomalies":          {LangEN: "anomalies", LangSV: "avvikelser"},
	"protocols.health.clean":       {LangEN: "every frame decoded", LangSV: "alla ramar avkodade"},
	"protocols.health.mostly":      {LangEN: "mostly decoded", LangSV: "mestadels avkodade"},
	"protocols.health.poor":        {LangEN: "many frames undecodable", LangSV: "många ramar kunde inte avkodas"},
	"class.read":                   {LangEN: "read", LangSV: "läsning"},
	"class.write":                  {LangEN: "write", LangSV: "skrivning"},
	"class.control":                {LangEN: "control", LangSV: "styrning"},
	"class.program":                {LangEN: "program", LangSV: "programmering"},
	"class.firmware":               {LangEN: "firmware", LangSV: "firmware"},
	"class.diagnostic":             {LangEN: "diagnostic", LangSV: "diagnostik"},
	"class.discovery":              {LangEN: "discovery", LangSV: "upptäckt"},
	"class.other":                  {LangEN: "other", LangSV: "övrigt"},
	"direction.request":            {LangEN: "request", LangSV: "förfrågan"},
	"direction.response":           {LangEN: "response", LangSV: "svar"},
	"direction.unknown":            {LangEN: "unknown", LangSV: "okänd"},
	"chart.protocols":              {LangEN: "Events by protocol", LangSV: "Händelser per protokoll"},
	"chart.classes":                {LangEN: "Operation mix", LangSV: "Operationsfördelning"},
	"chart.roles":                  {LangEN: "Assets by role", LangSV: "Tillgångar per roll"},
	"chart.vendors":                {LangEN: "Assets by vendor", LangSV: "Tillgångar per tillverkare"},
	"chart.operations":             {LangEN: "Most frequent operations", LangSV: "Vanligaste operationerna"},
	"chart.exceptions":             {LangEN: "Protocol errors", LangSV: "Protokollfel"},
	"chart.timeline":               {LangEN: "Events over time", LangSV: "Händelser över tid"},
	"chart.ports":                  {LangEN: "Server ports", LangSV: "Serverportar"},
	"chart.of_total":               {LangEN: "of all events", LangSV: "av alla händelser"},
	"settings.title":               {LangEN: "Settings", LangSV: "Inställningar"},
	"settings.saved":               {LangEN: "Settings saved.", LangSV: "Inställningarna sparades."},
	"settings.scope":               {LangEN: "Settings are stored in the project database and apply to everyone who opens this GUI; there are no user accounts yet.", LangSV: "Inställningarna lagras i projektdatabasen och gäller för alla som öppnar detta gränssnitt; det finns inga användarkonton än."},
	"settings.save":                {LangEN: "Save", LangSV: "Spara"},
	"settings.reset":               {LangEN: "Reset to defaults", LangSV: "Återställ standardvärden"},
	"settings.about":               {LangEN: "This project", LangSV: "Detta projekt"},
	"settings.project":             {LangEN: "Project", LangSV: "Projekt"},
	"settings.database":            {LangEN: "Database", LangSV: "Databas"},
	"settings.listen":              {LangEN: "Listening on", LangSV: "Lyssnar på"},
	"settings.schema":              {LangEN: "Schema version", LangSV: "Schemaversion"},
	"settings.passive":             {LangEN: "otinv never sends packets, so nothing here can reach an analysed device.", LangSV: "otinv skickar aldrig paket, så inget här kan nå en analyserad enhet."},
	"settings.on":                  {LangEN: "On", LangSV: "På"},
	"settings.off":                 {LangEN: "Off", LangSV: "Av"},
	"settings.group.appearance":    {LangEN: "Appearance", LangSV: "Utseende"},
	"settings.group.layout":        {LangEN: "Layout", LangSV: "Layout"},
	"settings.group.charts":        {LangEN: "Charts", LangSV: "Diagram"},
	"settings.group.tables":        {LangEN: "Tables and formats", LangSV: "Tabeller och format"},
	"settings.theme":               {LangEN: "Theme", LangSV: "Tema"},
	"settings.theme.help":          {LangEN: "Automatic follows the operating system.", LangSV: "Automatiskt följer operativsystemet."},
	"settings.theme.auto":          {LangEN: "Automatic", LangSV: "Automatiskt"},
	"settings.theme.light":         {LangEN: "Light", LangSV: "Ljust"},
	"settings.theme.dark":          {LangEN: "Dark", LangSV: "Mörkt"},
	"settings.accent":              {LangEN: "Accent colour", LangSV: "Accentfärg"},
	"settings.accent.help":         {LangEN: "Links, selected rows and the first chart colour.", LangSV: "Länkar, markerade rader och diagrammens första färg."},
	"settings.accent.blue":         {LangEN: "Blue", LangSV: "Blå"},
	"settings.accent.teal":         {LangEN: "Teal", LangSV: "Turkos"},
	"settings.accent.violet":       {LangEN: "Violet", LangSV: "Violett"},
	"settings.accent.amber":        {LangEN: "Amber", LangSV: "Bärnsten"},
	"settings.accent.crimson":      {LangEN: "Crimson", LangSV: "Karmosin"},
	"settings.accent.slate":        {LangEN: "Slate", LangSV: "Skiffer"},
	"settings.contrast":            {LangEN: "Contrast", LangSV: "Kontrast"},
	"settings.contrast.help":       {LangEN: "High contrast strengthens borders and text against the background.", LangSV: "Hög kontrast förstärker kanter och text mot bakgrunden."},
	"settings.contrast.normal":     {LangEN: "Normal", LangSV: "Normal"},
	"settings.contrast.high":       {LangEN: "High", LangSV: "Hög"},
	"settings.density":             {LangEN: "Density", LangSV: "Täthet"},
	"settings.density.help":        {LangEN: "How much padding rows, cells and panels get.", LangSV: "Hur mycket luft rader, celler och paneler får."},
	"settings.density.compact":     {LangEN: "Compact", LangSV: "Kompakt"},
	"settings.density.regular":     {LangEN: "Regular", LangSV: "Normal"},
	"settings.density.roomy":       {LangEN: "Roomy", LangSV: "Luftig"},
	"settings.font":                {LangEN: "Text size", LangSV: "Textstorlek"},
	"settings.font.help":           {LangEN: "The base size everything else is measured from.", LangSV: "Basstorleken som allt annat utgår från."},
	"settings.font.small":          {LangEN: "Small", LangSV: "Liten"},
	"settings.font.regular":        {LangEN: "Regular", LangSV: "Normal"},
	"settings.font.large":          {LangEN: "Large", LangSV: "Stor"},
	"settings.stripes":             {LangEN: "Striped rows", LangSV: "Tonade varannan rad"},
	"settings.stripes.help":        {LangEN: "Shade every other row, which helps on wide tables.", LangSV: "Tona varannan rad, vilket hjälper i breda tabeller."},
	"settings.monospace":           {LangEN: "Fixed width addresses", LangSV: "Fast teckenbredd för adresser"},
	"settings.monospace.help":      {LangEN: "Addresses, digests and identifiers line up under each other.", LangSV: "Adresser, kontrollsummor och identifierare hamnar under varandra."},
	"settings.charts":              {LangEN: "Draw charts", LangSV: "Visa diagram"},
	"settings.charts.help":         {LangEN: "With charts off, every number is still in its table.", LangSV: "Med diagram av finns varje tal kvar i sin tabell."},
	"settings.chart_size":          {LangEN: "Chart height", LangSV: "Diagramhöjd"},
	"settings.chart_size.help":     {LangEN: "How tall the timeline is drawn.", LangSV: "Hur hög tidslinjen ritas."},
	"settings.chart_size.short":    {LangEN: "Short", LangSV: "Låg"},
	"settings.chart_size.regular":  {LangEN: "Regular", LangSV: "Normal"},
	"settings.chart_size.tall":     {LangEN: "Tall", LangSV: "Hög"},
	"settings.buckets":             {LangEN: "Timeline intervals", LangSV: "Intervall i tidslinjen"},
	"settings.buckets.help":        {LangEN: "More intervals show shorter bursts.", LangSV: "Fler intervall visar kortare förlopp."},
	"settings.matrix_size":         {LangEN: "Matrix endpoints", LangSV: "Ändpunkter i matrisen"},
	"settings.matrix_size.help":    {LangEN: "How many of the busiest endpoints the matrix shows.", LangSV: "Hur många av de mest aktiva ändpunkterna matrisen visar."},
	"settings.page_size":           {LangEN: "Rows per page", LangSV: "Rader per sida"},
	"settings.page_size.help":      {LangEN: "Applies to the asset, flow and event tables.", LangSV: "Gäller tabellerna för tillgångar, flöden och händelser."},
	"settings.numbers":             {LangEN: "Thousands separator", LangSV: "Tusentalsavgränsare"},
	"settings.numbers.help":        {LangEN: "Grouped digits read more easily; plain digits copy and paste into a script.", LangSV: "Grupperade siffror läses lättare; oavbrutna siffror kan kopieras in i ett skript."},
	"settings.numbers.grouped":     {LangEN: "Grouped", LangSV: "Grupperade"},
	"settings.numbers.plain":       {LangEN: "Plain", LangSV: "Oavbrutna"},
	"settings.time_format":         {LangEN: "Timestamps", LangSV: "Tidsstämplar"},
	"settings.time_format.help":    {LangEN: "All times are UTC, which is how they are stored.", LangSV: "Alla tider är UTC, så som de lagras."},
	"settings.time_format.iso":     {LangEN: "Date and time", LangSV: "Datum och tid"},
	"settings.time_format.short":   {LangEN: "Short", LangSV: "Kort"},
	"settings.time_format.precise": {LangEN: "Microseconds", LangSV: "Mikrosekunder"},
	"settings.lang":                {LangEN: "Language", LangSV: "Språk"},
	"settings.lang.help":           {LangEN: "A link with ?lang= overrides this for one page.", LangSV: "En länk med ?lang= åsidosätter detta för en sida."},
	"settings.lang.en":             {LangEN: "English", LangSV: "Engelska"},
	"settings.lang.sv":             {LangEN: "Swedish", LangSV: "Svenska"},
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
