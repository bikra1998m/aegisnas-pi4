package models

import "time"

type User struct {
	ID        int       `json:"id"`
	Username  string    `json:"username"`
	Password  string    `json:"-"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

type Session struct {
	ID              string     `json:"id"`
	Username        string     `json:"username"`
	MAC             string     `json:"mac"`
	IP              string     `json:"ip"`
	AuthMethod      string     `json:"auth_method"`
	VLAN            int        `json:"vlan"`
	Role            string     `json:"role"`
	BandwidthProfile string    `json:"bandwidth_profile"`
	StartTime       time.Time  `json:"start_time"`
	EndTime         *time.Time `json:"end_time"`
	StopReason      string     `json:"stop_reason"`
}

type AuditLog struct {
	ID        int       `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	User      string    `json:"user"`
	Action    string    `json:"action"`
	Details   string    `json:"details"`
	Result    string    `json:"result"`
}