package dnsmasq

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Lease struct {
	ExpiresAt        string `json:"expires_at"`
	RemainingSeconds int64  `json:"remaining_seconds"`
	MAC              string `json:"mac"`
	IP               string `json:"ip"`
	Hostname         string `json:"hostname"`
	ClientID         string `json:"client_id"`
	Reservation      bool   `json:"reservation"`
	Expired          bool   `json:"expired"`
}

func ParseLeasesFile(path string, now time.Time, reservations map[string]struct{}) ([]Lease, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []Lease{}, nil
		}
		return nil, fmt.Errorf("open dnsmasq leases: %w", err)
	}
	defer file.Close()

	leases := []Lease{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lease, err := parseLeaseLine(line, now, reservations)
		if err != nil {
			return nil, err
		}
		leases = append(leases, lease)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan dnsmasq leases: %w", err)
	}

	sort.SliceStable(leases, func(i, j int) bool {
		if leases[i].Expired != leases[j].Expired {
			return !leases[i].Expired
		}
		if leases[i].IP != leases[j].IP {
			return leases[i].IP < leases[j].IP
		}
		return leases[i].MAC < leases[j].MAC
	})

	return leases, nil
}

func parseLeaseLine(line string, now time.Time, reservations map[string]struct{}) (Lease, error) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return Lease{}, fmt.Errorf("dnsmasq lease line %q is incomplete", line)
	}

	expiry, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return Lease{}, fmt.Errorf("parse dnsmasq lease expiry %q: %w", fields[0], err)
	}

	mac := normalizeLeaseMAC(fields[1])
	ip := fields[2]
	hostname := normalizeLeaseToken(fields[3])
	clientID := normalizeLeaseToken(fields[4])

	lease := Lease{
		MAC:         mac,
		IP:          ip,
		Hostname:    hostname,
		ClientID:    clientID,
		Reservation: reservationMatch(reservations, mac, ip),
	}

	if expiry <= 0 {
		lease.ExpiresAt = "never"
		return lease, nil
	}

	expiresAt := time.Unix(expiry, 0).UTC()
	lease.ExpiresAt = expiresAt.Format(time.RFC3339)
	lease.RemainingSeconds = expiry - now.Unix()
	lease.Expired = lease.RemainingSeconds <= 0
	return lease, nil
}

func normalizeLeaseToken(value string) string {
	if value == "*" {
		return ""
	}
	return value
}

func normalizeLeaseMAC(value string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "-", ":"))
}

func reservationMatch(reservations map[string]struct{}, mac, ip string) bool {
	if len(reservations) == 0 {
		return false
	}
	if _, ok := reservations["mac:"+mac]; ok {
		return true
	}
	if _, ok := reservations["ip:"+ip]; ok {
		return true
	}
	return false
}
