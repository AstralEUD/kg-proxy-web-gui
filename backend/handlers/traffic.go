package handlers

import (
	"fmt"
	"kg-proxy-web-gui/backend/services"
	"net/http"

	"github.com/gofiber/fiber/v2"
)

// GetTrafficData returns eBPF collected traffic data
func (h *Handler) GetTrafficData(c *fiber.Ctx) error {
	if h.EBPF == nil {
		return c.Status(http.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "eBPF service not initialized",
		})
	}

	data := h.EBPF.GetTrafficData()

	// Convert to frontend format
	var trafficList []map[string]interface{}
	for _, entry := range data {
		trafficList = append(trafficList, map[string]interface{}{
			"ip":          entry.SourceIP,
			"port":        entry.DestPort,
			"countryCode": entry.CountryCode,
			"countryName": getCountryName(entry.CountryCode),
			"pps":         entry.PacketCount,
			"total_bytes": formatBytes(entry.ByteCount),
			"status":      getStatus(entry.Blocked),
			"last_seen":   entry.Timestamp.Format("2006-01-02 15:04:05"),
			"risk_score":  calculateRiskScore(entry),
		})
	}

	return c.JSON(fiber.Map{
		"data":    trafficList,
		"enabled": h.EBPF.IsEnabled(),
		"stats":   h.EBPF.GetStats(),
	})
}

// ResetTrafficStats manually resets traffic statistics
func (h *Handler) ResetTrafficStats(c *fiber.Ctx) error {
	if h.EBPF == nil {
		return c.Status(http.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "eBPF service not initialized",
		})
	}

	if err := h.EBPF.ResetTrafficStats(); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to reset stats: %v", err),
		})
	}

	return c.JSON(fiber.Map{
		"message": "Traffic statistics reset successfully",
	})
}

func getCountryName(code string) string {
	countryMap := map[string]string{
		"AF": "Afghanistan", "AX": "Aland Islands", "AL": "Albania", "DZ": "Algeria", "AS": "American Samoa",
		"AD": "Andorra", "AO": "Angola", "AI": "Anguilla", "AQ": "Antarctica", "AG": "Antigua and Barbuda",
		"AR": "Argentina", "AM": "Armenia", "AW": "Aruba", "AU": "Australia", "AT": "Austria",
		"AZ": "Azerbaijan", "BS": "Bahamas", "BH": "Bahrain", "BD": "Bangladesh", "BB": "Barbados",
		"BY": "Belarus", "BE": "Belgium", "BZ": "Belize", "BJ": "Benin", "BM": "Bermuda",
		"BT": "Bhutan", "BO": "Bolivia", "BQ": "Bonaire, Sint Eustatius and Saba", "BA": "Bosnia and Herzegovina", "BW": "Botswana",
		"BV": "Bouvet Island", "BR": "Brazil", "IO": "British Indian Ocean Territory", "BN": "Brunei Darussalam", "BG": "Bulgaria",
		"BF": "Burkina Faso", "BI": "Burundi", "KH": "Cambodia", "CM": "Cameroon", "CA": "Canada",
		"CV": "Cape Verde", "KY": "Cayman Islands", "CF": "Central African Republic", "TD": "Chad", "CL": "Chile",
		"CN": "China", "CX": "Christmas Island", "CC": "Cocos (Keeling) Islands", "CO": "Colombia", "KM": "Comoros",
		"CG": "Congo", "CD": "Congo, Democratic Republic of the Congo", "CK": "Cook Islands", "CR": "Costa Rica", "CI": "Cote D'Ivoire",
		"HR": "Croatia", "CU": "Cuba", "CW": "Curacao", "CY": "Cyprus", "CZ": "Czech Republic",
		"DK": "Denmark", "DJ": "Djibouti", "DM": "Dominica", "DO": "Dominican Republic", "EC": "Ecuador",
		"EG": "Egypt", "SV": "El Salvador", "GQ": "Equatorial Guinea", "ER": "Eritrea", "EE": "Estonia",
		"ET": "Ethiopia", "FK": "Falkland Islands (Malvinas)", "FO": "Faroe Islands", "FJ": "Fiji", "FI": "Finland",
		"FR": "France", "GF": "French Guiana", "PF": "French Polynesia", "TF": "French Southern Territories", "GA": "Gabon",
		"GM": "Gambia", "GE": "Georgia", "DE": "Germany", "GH": "Ghana", "GI": "Gibraltar",
		"GR": "Greece", "GL": "Greenland", "GD": "Grenada", "GP": "Guadeloupe", "GU": "Guam",
		"GT": "Guatemala", "GG": "Guernsey", "GN": "Guinea", "GW": "Guinea-Bissau", "GY": "Guyana",
		"HT": "Haiti", "HM": "Heard Island and Mcdonald Islands", "VA": "Holy See (Vatican City State)", "HN": "Honduras", "HK": "Hong Kong",
		"HU": "Hungary", "IS": "Iceland", "IN": "India", "ID": "Indonesia", "IR": "Iran, Islamic Republic of",
		"IQ": "Iraq", "IE": "Ireland", "IM": "Isle of Man", "IL": "Israel", "IT": "Italy",
		"JM": "Jamaica", "JP": "Japan", "JE": "Jersey", "JO": "Jordan", "KZ": "Kazakhstan",
		"KE": "Kenya", "KI": "Kiribati", "KP": "Korea, Democratic People's Republic of", "KR": "South Korea", "XK": "Kosovo",
		"KW": "Kuwait", "KG": "Kyrgyzstan", "LA": "Lao People's Democratic Republic", "LV": "Latvia", "LB": "Lebanon",
		"LS": "Lesotho", "LR": "Liberia", "LY": "Libyan Arab Jamahiriya", "LI": "Liechtenstein", "LT": "Lithuania",
		"LU": "Luxembourg", "MO": "Macao", "MK": "Macedonia, the Former Yugoslav Republic of", "MG": "Madagascar", "MW": "Malawi",
		"MY": "Malaysia", "MV": "Maldives", "ML": "Mali", "MT": "Malta", "MH": "Marshall Islands",
		"MQ": "Martinique", "MR": "Mauritania", "MU": "Mauritius", "YT": "Mayotte", "MX": "Mexico",
		"FM": "Micronesia, Federated States of", "MD": "Moldova, Republic of", "MC": "Monaco", "MN": "Mongolia", "ME": "Montenegro",
		"MS": "Montserrat", "MA": "Morocco", "MZ": "Mozambique", "MM": "Myanmar", "NA": "Namibia",
		"NR": "Nauru", "NP": "Nepal", "NL": "Netherlands", "AN": "Netherlands Antilles", "NC": "New Caledonia",
		"NZ": "New Zealand", "NI": "Nicaragua", "NE": "Niger", "NG": "Nigeria", "NU": "Niue",
		"NF": "Norfolk Island", "MP": "Northern Mariana Islands", "NO": "Norway", "OM": "Oman", "PK": "Pakistan",
		"PW": "Palau", "PS": "Palestinian Territory, Occupied", "PA": "Panama", "PG": "Papua New Guinea", "PY": "Paraguay",
		"PE": "Peru", "PH": "Philippines", "PN": "Pitcairn", "PL": "Poland", "PT": "Portugal",
		"PR": "Puerto Rico", "QA": "Qatar", "RE": "Reunion", "RO": "Romania", "RU": "Russia",
		"RW": "Rwanda", "BL": "Saint Barthelemy", "SH": "Saint Helena", "KN": "Saint Kitts and Nevis", "LC": "Saint Lucia",
		"MF": "Saint Martin", "PM": "Saint Pierre and Miquelon", "VC": "Saint Vincent and the Grenadines", "WS": "Samoa", "SM": "San Marino",
		"ST": "Sao Tome and Principe", "SA": "Saudi Arabia", "SN": "Senegal", "RS": "Serbia", "CS": "Serbia and Montenegro",
		"SC": "Seychelles", "SL": "Sierra Leone", "SG": "Singapore", "SX": "Sint Maarten", "SK": "Slovakia",
		"SI": "Slovenia", "SB": "Solomon Islands", "SO": "Somalia", "ZA": "South Africa", "GS": "South Georgia and the South Sandwich Islands",
		"SS": "South Sudan", "ES": "Spain", "LK": "Sri Lanka", "SD": "Sudan", "SR": "Suriname",
		"SJ": "Svalbard and Jan Mayen", "SZ": "Swaziland", "SE": "Sweden", "CH": "Switzerland", "SY": "Syrian Arab Republic",
		"TW": "Taiwan", "TJ": "Tajikistan", "TZ": "Tanzania, United Republic of", "TH": "Thailand", "TL": "Timor-Leste",
		"TG": "Togo", "TK": "Tokelau", "TO": "Tonga", "TT": "Trinidad and Tobago", "TN": "Tunisia",
		"TR": "Turkey", "TM": "Turkmenistan", "TC": "Turks and Caicos Islands", "TV": "Tuvalu", "UG": "Uganda",
		"UA": "Ukraine", "AE": "United Arab Emirates", "GB": "United Kingdom", "US": "United States", "UM": "United States Minor Outlying Islands",
		"UY": "Uruguay", "UZ": "Uzbekistan", "VU": "Vanuatu", "VE": "Venezuela", "VN": "Vietnam",
		"VG": "Virgin Islands, British", "VI": "Virgin Islands, U.s.", "WF": "Wallis and Futuna", "EH": "Western Sahara", "YE": "Yemen",
		"ZM": "Zambia", "ZW": "Zimbabwe",
	}
	if name, ok := countryMap[code]; ok {
		return name
	}
	return code
}

func getStatus(blocked bool) string {
	if blocked {
		return "blocked"
	}
	return "allowed"
}

func formatBytes(bytes int64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	} else if bytes < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024.0)
	} else {
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1024.0*1024.0))
	}
}

func calculateRiskScore(entry services.TrafficEntry) int {
	score := 0
	if entry.Blocked {
		score += 10 // Basic block score
	}
	if entry.PacketCount > 100 {
		score += 10
	}
	if entry.PacketCount > 1000 {
		score += 40
	}
	if entry.CountryCode == "CN" || entry.CountryCode == "RU" {
		score += 20
	}
	if score > 100 {
		score = 100
	}
	return score
}

// GetPortStats returns per-destination-port traffic statistics
func (h *Handler) GetPortStats(c *fiber.Ctx) error {
	if h.EBPF == nil {
		return c.Status(http.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "eBPF service not initialized",
		})
	}

	stats := h.EBPF.GetPortStats()
	if stats == nil {
		stats = []services.PortStats{}
	}

	return c.JSON(fiber.Map{
		"ports": stats,
		"count": len(stats),
	})
}
