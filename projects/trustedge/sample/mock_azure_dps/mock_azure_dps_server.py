#!/usr/bin/env python3
"""
Azure DPS Mock Server for TrustEdge Testing

This mock server simulates the Azure Device Provisioning Service (DPS) REST API
for testing device registration flows.

Usage:
  python3 mock_azure_dps_server.py [options]

Options:
  --port PORT           Server port (default: 8443)
  --cert FILE           TLS certificate file (default: server.pem)
  --key FILE            TLS private key file (default: server.key)
  --ca FILE             CA certificate for client auth (optional)
  --scenario SCENARIO   Default test scenario (default: success_pending)
  --responses-dir DIR   Directory containing response JSON files

Scenarios:
  success_immediate     Return 200 "assigned" immediately
  success_pending       Return 202 "assigning", then 200 "assigned" after polling
  always_pending        Return 202 "assigning" forever (never completes)
  assignment_failed     Return 202 "assigning", then fail on poll
  unauthorized          Return 401 unauthorized
  tpm_challenge         Return 401 with TPM challenge
  quota_exceeded        Return 429 throttled
  server_error          Return 500 server error
  device_disabled       Return 403 forbidden
  not_found             Return 404 not found
  bad_request           Return 400 bad request
  service_unavailable   Return 503 unavailable

Environment Variables:
  AZURE_DPS_SCENARIO    Override default scenario
  AZURE_DPS_POLL_COUNT  Number of "assigning" responses before "assigned" (default: 2)
"""

import argparse
import json
import os
import re
import ssl
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Globals for state management
operation_states = {}  # Track polling state per operationId
poll_count_default = 2
current_scenario = "success_pending"

RESPONSES_DIR = os.path.join(os.path.dirname(__file__), "responses")


def load_response(filename, replacements=None):
  """Load a JSON response file and optionally perform substitutions."""
  filepath = os.path.join(RESPONSES_DIR, filename)
  with open(filepath, 'r') as f:
    content = f.read()

  if replacements:
    for key, value in replacements.items():
      content = content.replace(f"{{{{{key}}}}}", value)

  return json.loads(content)


class AzureDPSHandler(BaseHTTPRequestHandler):
  """HTTP request handler for Azure DPS mock endpoints."""

  # Suppress default logging
  def log_message(self, format, *args):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {args[0]}")

  def send_json_response(self, status_code, data, extra_headers=None):
    """Send a JSON response with the given status code."""
    body = json.dumps(data, indent=2).encode('utf-8')
    self.send_response(status_code)
    self.send_header('Content-Type', 'application/json; charset=utf-8')
    self.send_header('Content-Length', len(body))
    if extra_headers:
      for key, value in extra_headers.items():
        self.send_header(key, value)
    self.end_headers()
    self.wfile.write(body)

  def parse_dps_path(self, path):
    """Parse Azure DPS style URL path.

    Expected formats:
      /{idScope}/registrations/{registrationId}/register?api-version=...
      /{idScope}/registrations/{registrationId}/operations/{operationId}?api-version=...
    """
    parsed = urlparse(path)
    query = parse_qs(parsed.query)

    # Pattern for registration
    register_match = re.match(
      r'^/([^/]+)/registrations/([^/]+)/register$',
      parsed.path
    )
    if register_match:
      return {
        'type': 'register',
        'id_scope': register_match.group(1),
        'registration_id': register_match.group(2),
        'api_version': query.get('api-version', [''])[0]
      }

    # Pattern for operation status
    opstatus_match = re.match(
      r'^/([^/]+)/registrations/([^/]+)/operations/([^/]+)$',
      parsed.path
    )
    if opstatus_match:
      return {
        'type': 'operation_status',
        'id_scope': opstatus_match.group(1),
        'registration_id': opstatus_match.group(2),
        'operation_id': opstatus_match.group(3),
        'api_version': query.get('api-version', [''])[0]
      }

    return None

  def get_scenario(self):
    """Get the current test scenario from environment or query params."""
    # Check for scenario override in query string
    parsed = urlparse(self.path)
    query = parse_qs(parsed.query)
    scenario = query.get('scenario', [None])[0]

    if scenario:
      return scenario

    # Check environment variable
    return os.environ.get('AZURE_DPS_SCENARIO', current_scenario)

  def do_PUT(self):
    """Handle PUT requests (device registration)."""
    path_info = self.parse_dps_path(self.path)

    if not path_info or path_info['type'] != 'register':
      self.send_json_response(400, {
        "errorCode": 400000,
        "message": "Invalid request path"
      })
      return

    # Read request body
    content_length = int(self.headers.get('Content-Length', 0))
    body = self.rfile.read(content_length) if content_length > 0 else b''

    print(f"Registration request for: {path_info['registration_id']}")
    if body:
      print(f"Request body: {body.decode('utf-8', errors='replace')}")

    scenario = self.get_scenario()
    replacements = {
      'REGISTRATION_ID': path_info['registration_id'],
      'DEVICE_ID': path_info['registration_id']
    }

    # Handle different scenarios
    if scenario == 'success_immediate':
      response = load_response('register_200_assigned.json', replacements)
      self.send_json_response(200, response)

    elif scenario == 'success_pending':
      response = load_response('register_202_assigning.json', replacements)
      op_id = response['operationId']
      operation_states[op_id] = {'poll_count': 0, 'registration_id': path_info['registration_id']}
      self.send_json_response(202, response, {'Retry-After': '2'})

    elif scenario == 'unauthorized':
      response = load_response('register_401_unauthorized.json', replacements)
      self.send_json_response(401, response)

    elif scenario == 'tpm_challenge':
      response = load_response('register_401_tpm_challenge.json', replacements)
      self.send_json_response(401, response)

    elif scenario == 'quota_exceeded':
      response = load_response('error_429_throttled.json', replacements)
      self.send_json_response(429, response, {'Retry-After': '10'})

    elif scenario == 'server_error':
      response = load_response('error_500_server.json', replacements)
      self.send_json_response(500, response)

    elif scenario == 'device_disabled':
      response = load_response('error_403_forbidden.json', replacements)
      self.send_json_response(403, response)

    elif scenario == 'not_found':
      response = load_response('error_404_not_found.json', replacements)
      self.send_json_response(404, response)

    elif scenario == 'bad_request':
      response = load_response('error_400_bad_request.json', replacements)
      self.send_json_response(400, response)

    elif scenario == 'service_unavailable':
      response = load_response('error_503_unavailable.json', replacements)
      self.send_json_response(503, response)

    elif scenario == 'assignment_failed':
      response = load_response('register_202_assigning.json', replacements)
      op_id = response['operationId']
      operation_states[op_id] = {
        'poll_count': 0,
        'registration_id': path_info['registration_id'],
        'fail': True
      }
      self.send_json_response(202, response, {'Retry-After': '2'})

    elif scenario == 'always_pending':
      response = load_response('register_202_assigning.json', replacements)
      op_id = response['operationId']
      operation_states[op_id] = {
        'poll_count': 0,
        'registration_id': path_info['registration_id'],
        'always_pending': True
      }
      self.send_json_response(202, response, {'Retry-After': '2'})

    else:
      # Default to success_pending
      response = load_response('register_202_assigning.json', replacements)
      op_id = response['operationId']
      operation_states[op_id] = {'poll_count': 0, 'registration_id': path_info['registration_id']}
      self.send_json_response(202, response, {'Retry-After': '2'})

  def do_GET(self):
    """Handle GET requests (operation status lookup)."""
    path_info = self.parse_dps_path(self.path)

    if not path_info or path_info['type'] != 'operation_status':
      self.send_json_response(400, {
        "errorCode": 400000,
        "message": "Invalid request path"
      })
      return

    op_id = path_info['operation_id']
    print(f"Operation status check for: {op_id}")

    replacements = {
      'REGISTRATION_ID': path_info['registration_id'],
      'DEVICE_ID': path_info['registration_id']
    }

    # Check if we have state for this operation
    if op_id not in operation_states:
      # Check for "full" operation IDs that include the base ID
      base_op_id = None
      for stored_id in operation_states:
        if stored_id in op_id or op_id in stored_id:
          base_op_id = stored_id
          break

      if base_op_id:
        op_id = base_op_id
      else:
        response = load_response('error_404_not_found.json', replacements)
        self.send_json_response(404, response)
        return

    state = operation_states[op_id]
    poll_count = state.get('poll_count', 0)
    should_fail = state.get('fail', False)
    always_pending = state.get('always_pending', False)
    poll_count_threshold = int(os.environ.get('AZURE_DPS_POLL_COUNT', poll_count_default))

    if always_pending or poll_count < poll_count_threshold:
      # Still assigning (always_pending never completes)
      state['poll_count'] = poll_count + 1
      response = load_response('opstatus_202_assigning.json', replacements)
      self.send_json_response(202, response, {'Retry-After': '2'})
    else:
      # Assignment complete (or failed)
      del operation_states[op_id]

      if should_fail:
        response = load_response('opstatus_200_failed.json', replacements)
      else:
        response = load_response('opstatus_200_assigned.json', replacements)

      self.send_json_response(200, response)


def run_server(port, certfile, keyfile, cafile=None):
  """Run the mock HTTPS server."""
  server_address = ('', port)
  httpd = HTTPServer(server_address, AzureDPSHandler)

  # Configure TLS
  context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
  context.load_cert_chain(certfile, keyfile)

  if cafile:
    context.load_verify_locations(cafile)
    context.verify_mode = ssl.CERT_OPTIONAL

  httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

  print(f"Azure DPS Mock Server running on https://localhost:{port}")
  print(f"Default scenario: {current_scenario}")
  print("Press Ctrl+C to stop")

  try:
    httpd.serve_forever()
  except KeyboardInterrupt:
    print("\nShutting down...")
    httpd.shutdown()


def main():
  global current_scenario, poll_count_default

  parser = argparse.ArgumentParser(
    description='Azure DPS Mock Server for TrustEdge Testing'
  )
  parser.add_argument('--port', type=int, default=9443,
            help='Server port (default: 9443)')
  parser.add_argument('--cert', default='server.pem',
            help='TLS certificate file (default: server.pem)')
  parser.add_argument('--key', default='server.key',
            help='TLS private key file (default: server.key)')
  parser.add_argument('--ca', default=None,
            help='CA certificate for client auth (optional)')
  parser.add_argument('--scenario', default='success_pending',
            choices=['success_immediate', 'success_pending', 'always_pending',
                 'unauthorized', 'tpm_challenge', 'quota_exceeded', 'server_error',
                 'device_disabled', 'not_found', 'bad_request',
                 'service_unavailable', 'assignment_failed'],
            help='Default test scenario (default: success_pending)')
  parser.add_argument('--poll-count', type=int, default=2,
            help='Number of polling attempts before assignment (default: 2)')
  parser.add_argument('--responses-dir',
            help='Directory containing response JSON files')

  args = parser.parse_args()

  current_scenario = args.scenario
  poll_count_default = args.poll_count

  if args.responses_dir:
    global RESPONSES_DIR
    RESPONSES_DIR = args.responses_dir

  # Verify cert files exist
  if not os.path.exists(args.cert):
    print(f"Error: Certificate file not found: {args.cert}")
    print("Generate test certs with: ./generate_certs.sh")
    sys.exit(1)

  if not os.path.exists(args.key):
    print(f"Error: Key file not found: {args.key}")
    print("Generate test certs with: ./generate_certs.sh")
    sys.exit(1)

  run_server(args.port, args.cert, args.key, args.ca)


if __name__ == '__main__':
  main()
