# EP Webhooks

Real-time event notifications delivered to your endpoints via signed HTTP POST requests.

## Overview

The EP Webhooks system lets tenants register HTTPS endpoints to receive event notifications as they occur. Each delivery is signed with HMAC-SHA256 so you can verify authenticity, and the system automatically retries failed deliveries with exponential backoff.

## Registering an Endpoint

```
POST /api/cloud/webhooks
Authorization: Bearer ep_live_...

{
  "url": "https://example.com/webhooks/ep",
  "events": ["receipt.created", "commit.finalized", "dispute.opened"]
}
```

The response includes a `secret` field (format: `whsec_...`). **Store this immediately** — it is only shown once and is required to verify webhook signatures.

```json
{
  "endpoint": {
    "endpoint_id": "a1b2c3d4-...",
    "url": "https://example.com/webhooks/ep",
    "events": ["receipt.created", "commit.finalized", "dispute.opened"],
    "status": "active"
  },
  "secret": "whsec_abc123..."
}
```

## Managing Endpoints

| Method | Route | Description |
|--------|-------|-------------|
| `GET` | `/api/cloud/webhooks` | List all endpoints |
| `POST` | `/api/cloud/webhooks` | Create endpoint |
| `GET` | `/api/cloud/webhooks/:id` | Get endpoint details |
| `PUT` | `/api/cloud/webhooks/:id` | Update endpoint |
| `DELETE` | `/api/cloud/webhooks/:id` | Remove endpoint |
| `POST` | `/api/cloud/webhooks/:id/test` | Send test delivery |
| `GET` | `/api/cloud/webhooks/:id/deliveries` | List deliveries |

### Updating an Endpoint

You can update the URL, subscribed events, or status:

```
PUT /api/cloud/webhooks/:endpoint_id
Authorization: Bearer ep_live_...

{
  "url": "https://new-url.example.com/webhook",
  "events": ["receipt.created"],
  "status": "paused"
}
```

Endpoint status values: `active`, `paused`, `disabled`.

## Available Event Types

| Event Type | Description |
|------------|-------------|
| `receipt.created` | A new receipt has been issued |
| `commit.finalized` | A commit has been finalized |
| `dispute.opened` | A new dispute has been raised |
| `dispute.resolved` | A dispute has been resolved |
| `handshake.completed` | A handshake ceremony completed |
| `policy.updated` | A governance policy was changed |
| `webhook.test` | Test event (sent via the test endpoint) |

## Signature Verification

Every webhook delivery includes two headers for verification:

| Header | Description |
|--------|-------------|
| `X-EP-Signature` | HMAC-SHA256 hex digest |
| `X-EP-Timestamp` | Unix timestamp (seconds) of signing |
| `X-EP-Event` | The event type |
| `X-EP-Delivery` | Unique delivery ID |

The signature is computed as:

```
HMAC-SHA256(secret, timestamp + "." + JSON.stringify(payload))
```

### Verification Example (JavaScript / Node.js)

```javascript
const crypto = require('crypto');

function verifyWebhook(secret, signature, timestamp, body) {
  // Reject old timestamps (e.g. > 5 minutes) to prevent replay attacks
  const age = Math.floor(Date.now() / 1000) - parseInt(timestamp, 10);
  if (age > 300) {
    throw new Error('Webhook timestamp too old — possible replay attack');
  }

  const expected = crypto
    .createHmac('sha256', secret)
    .update(`${timestamp}.${body}`)
    .digest('hex');

  // Use timing-safe comparison
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
    throw new Error('Invalid webhook signature');
  }

  return JSON.parse(body);
}

// Express middleware example
app.post('/webhooks/ep', express.raw({ type: 'application/json' }), (req, res) => {
  try {
    const payload = verifyWebhook(
      process.env.EP_WEBHOOK_SECRET,
      req.headers['x-ep-signature'],
      req.headers['x-ep-timestamp'],
      req.body.toString(),
    );
    console.log('Verified event:', payload);
    res.status(200).send('OK');
  } catch (err) {
    console.error('Webhook verification failed:', err.message);
    res.status(400).send('Invalid signature');
  }
});
```

### Verification Example (Python)

```python
import hmac
import hashlib
import time
import json

def verify_webhook(secret: str, signature: str, timestamp: str, body: str) -> dict:
    # Reject old timestamps (> 5 minutes)
    age = int(time.time()) - int(timestamp)
    if age > 300:
        raise ValueError("Webhook timestamp too old - possible replay attack")

    expected = hmac.new(
        secret.encode(),
        f"{timestamp}.{body}".encode(),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(signature, expected):
        raise ValueError("Invalid webhook signature")

    return json.loads(body)

# Flask example
@app.route("/webhooks/ep", methods=["POST"])
def handle_webhook():
    try:
        payload = verify_webhook(
            secret=os.environ["EP_WEBHOOK_SECRET"],
            signature=request.headers["X-EP-Signature"],
            timestamp=request.headers["X-EP-Timestamp"],
            body=request.get_data(as_text=True),
        )
        print(f"Verified event: {payload}")
        return "OK", 200
    except ValueError as e:
        print(f"Webhook verification failed: {e}")
        return "Invalid signature", 400
```

## Retry Policy

Failed deliveries are retried with exponential backoff:

| Attempt | Retry After |
|---------|-------------|
| 1 | 1 minute |
| 2 | 5 minutes |
| 3 | 30 minutes |
| 4 | 2 hours |
| 5 | 12 hours |

After 5 failed attempts (including the initial delivery), the delivery is marked as permanently `failed`.

A delivery is considered failed if:
- The endpoint returns a non-2xx status code
- The request times out (15 seconds)
- A network error occurs

## Failure Handling

The system tracks consecutive failures per endpoint. After **10 consecutive failures**, the endpoint is automatically **disabled** to prevent unnecessary load.

To re-enable a disabled endpoint:

```
PUT /api/cloud/webhooks/:endpoint_id
Authorization: Bearer ep_live_...

{ "status": "active" }
```

Re-enabling resets the failure counter to zero.

## Testing

Use the test endpoint to verify your integration:

```
POST /api/cloud/webhooks/:endpoint_id/test
Authorization: Bearer ep_live_...
```

This sends a `webhook.test` event with a test payload to your endpoint and returns the delivery result.

## Viewing Delivery History

```
GET /api/cloud/webhooks/:endpoint_id/deliveries?limit=20&status=failed
Authorization: Bearer ep_live_...
```

Query parameters:
- `limit` — Maximum results (default: 50, max: 200)
- `status` — Filter by status: `pending`, `delivered`, `failed`, `retrying`

## Best Practices

1. **Always verify signatures** — Use the HMAC signature and timestamp to authenticate deliveries.
2. **Respond quickly** — Return a 2xx status within 15 seconds. Process events asynchronously if needed.
3. **Handle duplicates** — Use the `X-EP-Delivery` header to deduplicate. The same event may be delivered more than once during retries.
4. **Use HTTPS** — While HTTP is supported for development, always use HTTPS in production.
5. **Monitor your endpoint** — Check delivery history regularly and address failures before auto-disable kicks in.
