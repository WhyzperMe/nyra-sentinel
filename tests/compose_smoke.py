"""Exercise the Compose stack with synthetic events on an isolated loopback deployment."""

import datetime as dt
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
import uuid


def token(name):
    return Path('secrets', name).read_text().strip()


def api(path, credential=None, body=None, status=200):
    headers = {'Authorization': 'Bearer ' + token(credential)} if credential else {}
    data = None
    if body is not None:
        headers['Content-Type'] = 'application/json'
        data = json.dumps(body).encode()
    try:
        response = urlopen(Request('http://127.0.0.1:8765/api/v1/' + path, data, headers), timeout=5)
    except HTTPError as error:
        response = error
    with response:
        assert response.code == status, (path, response.code, status)
        return json.load(response)


def await_value(check):
    deadline = time.monotonic() + 50
    while time.monotonic() < deadline:
        try:
            value = check()
            if value:
                return value
        except (URLError, ConnectionError):
            pass
        time.sleep(0.5)
    raise AssertionError('condition did not become true within 50 seconds')


def tls(cert=None, key=None):
    context = ssl.create_default_context(cafile='pki/ca.crt')
    # TLS 1.2 surfaces missing/untrusted client certificates during the handshake itself.
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    if cert is not None:
        context.load_cert_chain(cert, key)
    return context


def send(context, lines):
    with socket.create_connection(('127.0.0.1', 6514), timeout=5) as conn:
        with context.wrap_socket(conn, server_hostname='127.0.0.1') as stream:
            # RFC 5425 TLS syslog uses the byte length followed by a space and the message.
            for line in lines:
                message = line.rstrip('\n').encode()
                stream.sendall(str(len(message)).encode() + b' ' + message)
            time.sleep(1)
            try:
                stream.unwrap().close()
            except ssl.SSLEOFError:
                pass  # Vector may close the TCP socket after reading close_notify.


def denied(context, line):
    try:
        send(context, [line])
    except ssl.SSLError:
        return
    raise AssertionError('mTLS accepted an unauthorized client')


def compose(*args, capture=False):
    return subprocess.run(['docker', 'compose', *args], check=True, timeout=90,
                          stdin=subprocess.DEVNULL, capture_output=capture, text=True)


def syslog(marker, source):
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')
    message = Path('fixtures/filterlog-ipv4-tcp.txt').read_text().strip().replace('10.13.37.156', source)
    return f'<134>1 {now} {marker} filterlog 1234 PROBE - {message}\n'


def main():
    assert 'SENTINEL_HOST_IP=127.0.0.1' in Path('.env').read_text().splitlines()
    marker = 'smoke-' + uuid.uuid4().hex[:10]
    source, during_outage = '8.8.8.8', '1.1.1.1'
    line = syslog(marker, source)
    denied(tls(), line)
    with tempfile.TemporaryDirectory() as tmp:
        cert, key = Path(tmp, 'cert.pem'), Path(tmp, 'key.pem')
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=untrusted-test-client', '-out', cert, '-keyout', key],
                       check=True, capture_output=True, timeout=15)
        denied(tls(cert, key), line)
    trusted = tls('pki/client/client.crt', 'pki/client/client.key')
    send(trusted, [line] * 12)

    def count_lines():
        rows = api('events?limit=100', 'api_token')['events']
        return rows if sum(row['hostname'] == marker for row in rows) == 12 else None

    raw = {row['event_id'] for row in await_value(count_lines) if row['hostname'] == marker}
    events = api('security-events?limit=100', 'api_token')['events']
    event = next(row for row in events if row['source_ip'] == source and row['raw_event_id'] in raw)
    assert event['category'] == 'firewall.filterlog' and event['action'] == 'block'
    def linked_detection():
        for row in api('detections', 'api_token')['items']:
            if row['entity_value'] == source:
                detail = api('detections/' + row['id'], 'api_token')
                if event['event_id'] in detail['evidence_security_event_ids']:
                    return row
        return None

    detection = await_value(linked_detection)
    api('incidents/' + detection['incident_id'], 'api_token')

    report = json.loads(compose('--profile', 'agent', 'run', '--rm', '-T', 'agent', '--ip', source,
                                '--no-llm', capture=True).stdout)
    assert event['event_id'] in report['investigation']['evidence_ids']
    api('harness/reports/' + report['storage']['id'], 'api_token')
    proposal = api('response/proposals', 'api_token', {
        'target_ip': source, 'evidence_event_id': event['event_id'], 'incident_id': detection['incident_id'],
        'justification': 'Synthetic isolated response workflow verification.', 'duration_minutes': 10,
        'requester': 'test-operator',
    }, 201)
    proposal_id = proposal['id']
    path = 'response/proposals/' + proposal_id
    api(path + '/approve', 'response_approval_token', {
        'actor': 'test-approver', 'confirm': 'APPROVED ' + proposal_id, 'reason': 'Synthetic test approval',
    })
    for action in ('simulate', 'rollback'):
        result = json.loads(compose('--profile', 'response', 'run', '--rm', '-T', 'response-gateway',
                                    action, proposal_id, 'test-gateway', capture=True).stdout)
        assert result['live_firewall_change'] is False
    assert api(path, 'api_token')['proposal']['status'] == 'rolled_back'

    compose('stop', 'sentinel')
    stopped = compose('ps', '-a', '--format', 'json', 'sentinel', capture=True).stdout.strip()
    service = json.loads(stopped)
    if isinstance(service, list):
        service = service[0]
    assert service['ExitCode'] == 0, 'Sentinel did not exit gracefully'
    send(trusted, [syslog(marker, during_outage)])
    time.sleep(3)
    compose('start', 'sentinel')
    await_value(lambda: any(row['source_ip'] == during_outage
                            for row in api('security-events', 'api_token')['events']))
    assert api(path, 'api_token')['proposal']['status'] == 'rolled_back'
    print('PASS Compose mTLS, distinct deliveries, detection, incident, agent, simulation, shutdown and buffered recovery')


if __name__ == '__main__':
    main()
