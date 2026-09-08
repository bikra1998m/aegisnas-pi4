package radius

import (
	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
)

// ExternalVendorIntakeVSASpecs converts a validated NAS-0073 intake report into
// bounded VSA codec specs. It deliberately exposes decode metadata only; live
// policy enforcement and vendor certification remain separate release steps.
func ExternalVendorIntakeVSASpecs(report productconfigs.ExternalVendorIntakeReport) ([]VendorAttributeSpec, error) {
	if err := productconfigs.ValidateExternalVendorIntakeReport(report); err != nil {
		return nil, err
	}
	specs := make([]VendorAttributeSpec, 0, report.Summary.RuntimeDecodableAttributes)
	for _, record := range report.Records {
		if record.Number == 0 || record.Number > 255 {
			continue
		}
		format := VendorAttributeFormat{
			TypeOctets:   record.WireCodec.TypeOctets,
			LengthOctets: record.WireCodec.LengthOctets,
		}.normalized()
		specs = append(specs, VendorAttributeSpec{
			VendorID: record.PEN,
			Type:     record.Number,
			WireType: record.WireType,
			Format:   format,
		})
	}
	return specs, nil
}
