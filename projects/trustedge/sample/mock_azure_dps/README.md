# Azure DPS Mock Server

Mock HTTPS server for testing Azure Device Provisioning Service (DPS) integration.

## Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| PUT | `/{idScope}/registrations/{registrationId}/register?api-version=2019-03-31` | Device registration |
| GET | `/{idScope}/registrations/{registrationId}/operations/{operationId}?api-version=2019-03-31` | Operation status lookup |

## Quick Start

```bash
# Generate test certificates (if needed)
cd projects/trustedge/sample/mock_azure_dps
./generate_certs.sh

# Run the mock server
python3 mock_azure_dps_server.py --port 8443 --cert server.pem --key server.key
```

## Test Scenarios

Configure the server behavior via query parameters or environment variables:

| Scenario | Environment Variable | Description |
|----------|---------------------|-------------|
| Success (immediate) | `AZURE_DPS_SCENARIO=success_immediate` | Returns 200 with assigned status |
| Success (pending) | `AZURE_DPS_SCENARIO=success_pending` | Returns 202 then 200 after polling |
| Unauthorized | `AZURE_DPS_SCENARIO=unauthorized` | Returns 401 error |
| Quota exceeded | `AZURE_DPS_SCENARIO=quota_exceeded` | Returns 429 with Retry-After |
| Server error | `AZURE_DPS_SCENARIO=server_error` | Returns 500 error |
| Device disabled | `AZURE_DPS_SCENARIO=device_disabled` | Returns 403 device disabled |
| Not found | `AZURE_DPS_SCENARIO=not_found` | Returns 404 error |

## Response Files

Pre-built JSON response files in `responses/` directory:
- `register_202_assigning.json` - Registration accepted, assigning
- `register_200_assigned.json` - Registration complete (immediate)
- `register_401_unauthorized.json` - Authentication failed
- `opstatus_202_assigning.json` - Still assigning
- `opstatus_200_assigned.json` - Assignment complete
- `error_400_bad_request.json` - Bad request
- `error_403_forbidden.json` - Device disabled
- `error_404_not_found.json` - Registration not found
- `error_429_throttled.json` - Rate limited
- `error_500_server.json` - Internal server error
