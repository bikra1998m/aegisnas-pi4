# Full AI Engine

AegisNAS keeps AI advisory. Authentication, authorization, accounting, CoA, disconnect, firewall, and shaping paths continue to work even if the AI provider is down.

Use full AI mode on high-capacity appliances or strong VMs where you want richer operational analysis than the local rule-based AI Lite checks.

## Modes

```yaml
ailite:
  enabled: true
  mode: "lite"
  provider: "local"
```

Use this for labs, branch boxes, and constrained hardware. It runs local checks for auth failures, session anomalies, and config linting.

```yaml
ailite:
  enabled: true
  mode: "full"
  provider: "openai-compatible"
  endpoint: "https://ai.example.net"
  model: "ops-model"
  api_key_env: "AEGIS_AI_API_KEY"
  request_timeout_seconds: 20
  max_input_events: 200
```

Use this for high-configuration appliances. The endpoint must expose an OpenAI-compatible `/v1/chat/completions` API. The endpoint can be a cloud AI provider or a local model server running on the appliance or nearby infrastructure.

## High Hardware Profile

For a new high-capacity VM or appliance:

```bash
bash scripts/ubuntu-vm-bootstrap.sh \
  --wan ens33 \
  --lan ens37 \
  --profile enterprise \
  --ai-mode full \
  --ai-endpoint https://ai.example.net \
  --ai-model ops-model
```

Put the provider key in the service environment:

```bash
sudo sed -i '/^AEGIS_AI_API_KEY=/d' /etc/default/aegisnas
sudo sh -c 'echo AEGIS_AI_API_KEY=replace-with-provider-key >> /etc/default/aegisnas'
sudo chmod 0640 /etc/default/aegisnas
sudo systemctl daemon-reload
sudo systemctl restart aegis-ai-lite
```

The systemd unit name remains `aegis-ai-lite` for compatibility, but the service now runs the selected AI engine mode.

## Admin UI

Open `Access Settings`, then set:

- `Profile`: Enterprise Edge
- `AI Engine Enabled`: on
- `AI Mode`: Full AI
- `AI Provider`: OpenAI Compatible
- `Full AI Endpoint`: provider base URL
- `Full AI Model`: model name
- `AI API Key Env`: `AEGIS_AI_API_KEY`

Save settings and restart the AI service:

```bash
sudo systemctl restart aegis-ai-lite
```

## Verification

```bash
systemctl --no-pager --full status aegis-ai-lite
curl -fsS http://127.0.0.1:8084/health
```

Open `AI Insights` in the admin UI. Full AI recommendations use source `ai_full`.

To trigger analysis immediately:

```bash
curl -fsS -X POST \
  -H "Authorization: Bearer ${AEGIS_ADMIN_BOOTSTRAP_TOKEN}" \
  http://127.0.0.1:8083/api/v1/ai-recommendations/run
```

If no endpoint or model is configured, the dashboard warns that full AI mode is not ready. Local AI Lite checks still protect the operator workflow with basic recommendations.

## Safety

Full AI receives a bounded operational snapshot:

- deployment profile and hardware hints
- non-secret service configuration
- runtime statuses
- recent audit events
- recent sessions
- recent alerts
- recent recommendations

Secrets such as RADIUS shared secrets, LDAP bind passwords, admin tokens, and provider keys are not included in the AI prompt.
