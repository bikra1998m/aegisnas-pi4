package radius

import (
	"fmt"
	"strings"
)

// The SQL driver escapes every attribute expansion using libpq. Keep all
// network-supplied text inside SQL literals; never interpolate SQL identifiers.
// radacct is the latest NAS snapshot, not the immutable accounting event ledger.
func postgresAccountingQueries() string {
	text := func(attr string) string { return "NULLIF('%{" + attr + "}', '')" }
	number := func(attr string) string { return "CAST('%{%{" + attr + "}:-0}' AS BIGINT)" }
	epoch := "COALESCE(NULLIF('%{integer:Event-Timestamp}', '')::BIGINT, %l - " + number("Acct-Delay-Time") + ")"
	eventTime := "(TO_TIMESTAMP(" + epoch + ") AT TIME ZONE 'UTC')"
	nas := "'%{%{NAS-IP-Address}:-%{%{NAS-IPv6-Address}:-%{%{Packet-Src-IP-Address}:-%{Packet-Src-IPv6-Address}}}}'"
	source := "'%{%{Packet-Src-IP-Address}:-%{Packet-Src-IPv6-Address}}'"
	// Scope the stock NAS/user/session digest by the authenticated packet source.
	// This is an identity namespace, not a cryptographic authentication primitive.
	// '|' is absent from typed IP addresses and the stock hexadecimal digest;
	// ':' would make the boundaries ambiguous for pairs of IPv6 addresses.
	uniqueID := "MD5(" + source + " || '|' || " + nas + " || '|' || '%{Acct-Unique-Session-Id}')"
	baseColumns := []string{"acctsessionid", "acctuniqueid", "username", "realm", "nasipaddress", "nasportid", "nasporttype", "aegis_packet_source", "aegis_session_id"}
	baseValues := []string{"'%{Acct-Session-Id}'", uniqueID, text("User-Name"), text("Realm"), nas,
		"NULLIF('%{%{NAS-Port-Id}:-%{NAS-Port}}', '')", text("NAS-Port-Type"), source, "('sql-' || " + uniqueID + ")"}
	metadata := [][2]string{
		{"acctauthentic", "Acct-Authentic"}, {"calledstationid", "Called-Station-Id"},
		{"callingstationid", "Calling-Station-Id"}, {"servicetype", "Service-Type"},
		{"framedprotocol", "Framed-Protocol"}, {"framedipaddress", "Framed-IP-Address"},
		{"framedipv6address", "Framed-IPv6-Address"}, {"framedipv6prefix", "Framed-IPv6-Prefix"},
		{"framedinterfaceid", "Framed-Interface-Id"}, {"delegatedipv6prefix", "Delegated-IPv6-Prefix"},
		{"framedroute", "Framed-Route"}, {"framedipv6route", "Framed-IPv6-Route"},
		{"class", "Class"}, {"acctmultisessionid", "Acct-Multi-Session-Id"},
	}
	for _, pair := range metadata {
		baseColumns = append(baseColumns, pair[0])
		baseValues = append(baseValues, text(pair[1]))
	}
	for _, pair := range [][2]string{{"acctinputoctets", "Acct-Input-Octets"}, {"acctoutputoctets", "Acct-Output-Octets"},
		{"acctinputgigawords", "Acct-Input-Gigawords"}, {"acctoutputgigawords", "Acct-Output-Gigawords"}, {"acctlinkcount", "Acct-Link-Count"}} {
		baseColumns = append(baseColumns, pair[0])
		baseValues = append(baseValues, number(pair[1]))
	}
	for _, direction := range []string{"Input", "Output"} {
		baseColumns = append(baseColumns, "aegis_"+strings.ToLower(direction)+"_octets_64")
		// NUMERIC avoids signed BIGINT overflow at 2^63. Raw 32-bit words and
		// the exact unsigned decimal text are retained for Go reconciliation.
		baseValues = append(baseValues, "CAST(("+number("Acct-"+direction+"-Gigawords")+"::NUMERIC * 4294967296 + "+number("Acct-"+direction+"-Octets")+") AS TEXT)")
	}
	var out strings.Builder
	out.WriteString("\tauto_escape = yes\n\tread_groups = no\n\tread_profiles = no\n\tsql_user_name = \"%{User-Name}\"\n")
	out.WriteString("\taccounting {\n\t\treference = \"%{tolower:type.%{Acct-Status-Type}.query}\"\n\t\ttype {\n")
	for _, kind := range []string{"start", "interim-update", "stop"} {
		columns := append([]string{}, baseColumns...)
		values := append([]string{}, baseValues...)
		duration, start, stop, connectStart, connectStop, cause := number("Acct-Session-Time"), eventTime, "NULL", "NULL", "NULL", "NULL"
		if kind == "start" {
			duration, connectStart = "0", text("Connect-Info")
		} else {
			start = "(" + eventTime + " - " + duration + " * INTERVAL '1 second')"
		}
		if kind == "stop" {
			stop, connectStop, cause = eventTime, text("Connect-Info"), "COALESCE("+text("Acct-Terminate-Cause")+", 'accounting-stop')"
		}
		columns = append(columns, "acctstarttime", "acctupdatetime", "acctstoptime", "acctsessiontime", "connectinfo_start", "connectinfo_stop", "acctterminatecause", "aegis_ingest_revision")
		values = append(values, start, eventTime, stop, duration, connectStart, connectStop, cause, "1")
		updates := []string{"acctstarttime = LEAST(radacct.acctstarttime, EXCLUDED.acctstarttime)",
			"connectinfo_start = COALESCE(radacct.connectinfo_start, EXCLUDED.connectinfo_start)",
			"aegis_ingest_revision = radacct.aegis_ingest_revision + 1", "aegis_reconcile_status = 'pending'",
			"aegis_reconcile_error = NULL", "aegis_reconciled_at = NULL", "updated_at = CURRENT_TIMESTAMP"}
		where := "radacct.aegis_packet_source = EXCLUDED.aegis_packet_source AND radacct.nasipaddress = EXCLUDED.nasipaddress"
		if kind != "start" {
			for _, column := range baseColumns[2:] {
				if column == "nasipaddress" || column == "aegis_packet_source" || column == "aegis_session_id" {
					continue
				}
				if kind == "interim-update" {
					// The WHERE clause already rejects older interims.
					updates = append(updates, column+" = COALESCE(EXCLUDED."+column+", radacct."+column+")")
				} else {
					updates = append(updates, column+" = COALESCE(CASE WHEN EXCLUDED.acctupdatetime >= radacct.acctupdatetime THEN EXCLUDED."+column+" END, radacct."+column+")")
				}
			}
			updates = append(updates, "acctupdatetime = GREATEST(radacct.acctupdatetime, EXCLUDED.acctupdatetime)",
				"acctsessiontime = GREATEST(radacct.acctsessiontime, EXCLUDED.acctsessiontime)")
			where += " AND radacct.acctstoptime IS NULL"
			if kind == "stop" {
				updates = append(updates, "acctstoptime = EXCLUDED.acctstoptime", "connectinfo_stop = EXCLUDED.connectinfo_stop", "acctterminatecause = EXCLUDED.acctterminatecause")
				where += " AND EXCLUDED.acctstoptime >= radacct.acctstarttime"
			} else {
				where += " AND (EXCLUDED.acctupdatetime > radacct.acctupdatetime OR (EXCLUDED.acctupdatetime = radacct.acctupdatetime AND EXCLUDED.acctsessiontime >= radacct.acctsessiontime AND (EXCLUDED.acctinputgigawords, EXCLUDED.acctinputoctets) >= (radacct.acctinputgigawords, radacct.acctinputoctets) AND (EXCLUDED.acctoutputgigawords, EXCLUDED.acctoutputoctets) >= (radacct.acctoutputgigawords, radacct.acctoutputoctets)))"
			}
		}
		query := "INSERT INTO radacct AS r (" + strings.Join(columns, ", ") + ") VALUES (" + strings.Join(values, ", ") + ") ON CONFLICT (acctuniqueid) DO UPDATE SET " + strings.Join(updates, ", ") + " WHERE " + where
		query = strings.ReplaceAll(query, "radacct.", "r.")
		fmt.Fprintf(&out, "\t\t\t%s {\n\t\t\t\tquery = \"%s\"\n\t\t\t}\n", kind, query)
	}
	for _, kind := range []string{"accounting-on", "accounting-off"} {
		query := "UPDATE radacct SET acctstoptime = " + eventTime + ", acctupdatetime = " + eventTime + ", acctsessiontime = GREATEST(acctsessiontime, EXTRACT(EPOCH FROM (" + eventTime + " - acctstarttime))::BIGINT), acctterminatecause = 'NAS-Reboot', aegis_ingest_revision = aegis_ingest_revision + 1, aegis_reconcile_status = 'pending', aegis_reconcile_error = NULL, aegis_reconciled_at = NULL, updated_at = CURRENT_TIMESTAMP WHERE acctstoptime IS NULL AND nasipaddress = " + nas + " AND aegis_packet_source = " + source + " AND acctstarttime <= " + eventTime + " AND acctupdatetime <= " + eventTime
		fmt.Fprintf(&out, "\t\t\t%s {\n\t\t\t\tquery = \"%s\"\n\t\t\t}\n", kind, query)
	}
	out.WriteString("\t\t}\n\t}\n\tpost-auth {\n")
	// Never collect passwords, challenge responses, or failure messages that
	// might embed credentials. Reply packet type alone records the outcome.
	postauth := "INSERT INTO radpostauth (username, reply, authdate, class, calledstationid, callingstationid, nasipaddress, nasidentifier, packet_type, realm) VALUES (COALESCE(" + text("User-Name") + ", ''), '%{reply:Packet-Type}', CURRENT_TIMESTAMP, " + text("reply:Class") + ", " + text("Called-Station-Id") + ", " + text("Calling-Station-Id") + ", " + nas + ", " + text("NAS-Identifier") + ", '%{reply:Packet-Type}', " + text("Realm") + ")"
	fmt.Fprintf(&out, "\t\tquery = \"%s\"\n\t}\n", postauth)
	return out.String()
}

const postgresAccountingUnlang = `
		if (!&Acct-Status-Type || (&Acct-Status-Type != Start && &Acct-Status-Type != Interim-Update && &Acct-Status-Type != Stop && &Acct-Status-Type != Accounting-On && &Acct-Status-Type != Accounting-Off)) {
			update control {
				Response-Packet-Type := Do-Not-Respond
			}
			return
		}
		if ((&Acct-Status-Type == Start || &Acct-Status-Type == Interim-Update || &Acct-Status-Type == Stop) && (!&Acct-Session-Id || !&Acct-Unique-Session-Id)) {
			update control {
				Response-Packet-Type := Do-Not-Respond
			}
			return
		}
		sql {
			fail = 1
			invalid = 1
		}
		if (fail || invalid) {
			update control {
				Response-Packet-Type := Do-Not-Respond
			}
			return
		}
		# A successful query can deliberately retain a newer/closed snapshot.
		# Acknowledge that no-op so the NAS need not retransmit stale packets.
		ok
`

const postgresPostAuthUnlang = `
		sql {
			fail = 1
			invalid = 1
			noop = 1
		}
		if (fail || invalid || noop) {
			reject
		}
		Post-Auth-Type REJECT {
			sql
		}
`
