package rules

// MITRE ATT&CK for ICS techniques referenced by the built-in rules.
//
// The table is transcribed from the published STIX bundle
// (https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json,
// collection "ICS ATT&CK", spec 3.3.0, retrieved 2026-10-14), so the
// identifiers and names are ATT&CK's own rather than anybody's memory of
// them. Several techniques this project would once have cited have since been
// restructured — "Unauthorized Command Message" is now T1692.001 under
// Unauthorized Message, "System Firmware" is T1693.001 under Modify Firmware
// — which is exactly why it is transcribed rather than recalled.
//
// Only the techniques the rules use are here; the full matrix is not this
// tool's job to carry.
var techniques = map[string]string{
	"T0813":     "Denial of Control",
	"T0814":     "Denial of Service",
	"T0816":     "Device Restart/Shutdown",
	"T0830":     "Adversary-in-the-Middle",
	"T0836":     "Modify Parameter",
	"T0843":     "Program Download",
	"T0845":     "Program Upload",
	"T0848":     "Rogue Master",
	"T0858":     "Change Operating Mode",
	"T0861":     "Point & Tag Identification",
	"T0881":     "Service Stop",
	"T0885":     "Commonly Used Port",
	"T0886":     "Remote Services",
	"T0889":     "Modify Program",
	"T1691.002": "Block Operational Technology Message: Reporting Message",
	"T1692.001": "Unauthorized Message: Command Message",
	"T1693.001": "Modify Firmware: System Firmware",
}

// TechniqueName returns the ATT&CK name of a technique id, or an empty string
// for one this build does not know.
func TechniqueName(id string) string { return techniques[id] }

// TechniqueURL links a technique to its page, which is where an analyst goes
// to read what it means. Sub-technique ids are written with a dot and linked
// with a slash.
func TechniqueURL(id string) string {
	if id == "" || techniques[id] == "" {
		return ""
	}
	path := ""
	for _, r := range id {
		if r == '.' {
			path += "/"
			continue
		}
		path += string(r)
	}
	return "https://attack.mitre.org/techniques/" + path
}
