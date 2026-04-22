package configs

import (
	_ "embed"
	"strconv"
	"strings"
)

//go:embed aegisnas-vendor.dictionery
var AegisNASVendorDictionaryText string

type VendorDictionary struct {
	Name       string
	ID         int
	Attributes []VendorDictionaryAttribute
}

type VendorDictionaryAttribute struct {
	Name   string
	Number int
	Type   string
}

func AegisNASVendorDictionary() VendorDictionary {
	dict, ok := ParseVendorDictionary(AegisNASVendorDictionaryText)
	if ok {
		return dict
	}
	return VendorDictionary{Name: "AegisNAS", ID: 55555}
}

func ParseVendorDictionary(text string) (VendorDictionary, bool) {
	var out VendorDictionary
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(stripDictionaryComment(line))
		if len(fields) == 0 {
			continue
		}
		switch strings.ToUpper(fields[0]) {
		case "VENDOR":
			if len(fields) < 3 {
				continue
			}
			id, err := strconv.Atoi(fields[2])
			if err != nil {
				continue
			}
			out.Name = fields[1]
			out.ID = id
		case "ATTRIBUTE":
			if len(fields) < 4 {
				continue
			}
			number, err := strconv.Atoi(fields[2])
			if err != nil {
				continue
			}
			out.Attributes = append(out.Attributes, VendorDictionaryAttribute{
				Name:   fields[1],
				Number: number,
				Type:   strings.ToLower(fields[3]),
			})
		}
	}
	return out, out.Name != "" && out.ID > 0 && len(out.Attributes) > 0
}

func stripDictionaryComment(line string) string {
	if idx := strings.Index(line, "#"); idx >= 0 {
		return line[:idx]
	}
	return line
}
