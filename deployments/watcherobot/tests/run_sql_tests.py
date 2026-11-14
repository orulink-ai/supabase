"""Run binding migrations in a new network-isolated PostgreSQL container only."""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import json
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]

def main():
    name = 'watcherobot-binding-test-' + uuid.uuid4().hex[:12]
    launch = ('set -eu; mkdir -p /test-data; chown postgres:postgres /test-data; '
              'gosu postgres initdb -D /test-data -U postgres --auth-local=trust --no-locale -E UTF8 >/dev/null; '
              'exec gosu postgres postgres -D /test-data -c unix_socket_directories=/tmp '
              '-c listen_addresses= -c shared_preload_libraries=')
    created = False
    try:
        subprocess.run(['docker','run','-d','--name',name,'--network','none',
                        '--label','org.orulink.purpose=binding-integration-test',
                        '--tmpfs','/test-data:rw,nosuid,size=512m','--entrypoint','/bin/sh',
                        'supabase/postgres:17.6.1.136','-c',launch],check=True,stdout=subprocess.DEVNULL)
        created = True
        for _ in range(60):
            ready = subprocess.run(['docker','exec',name,'pg_isready','-h','/tmp','-U','postgres'],capture_output=True)
            if ready.returncode == 0: break
            time.sleep(1)
        else: raise RuntimeError('Disposable database startup timed out')
        fixture = """create role anon; create role authenticated; create schema auth;
        create schema extensions; create extension pgcrypto with schema extensions;
        create table auth.users(id uuid primary key);
        create function auth.uid() returns uuid language sql stable as
        $$select nullif(current_setting('request.jwt.claim.sub',true),'')::uuid$$;
        """
        files = sorted((ROOT/'migrations').glob('*.sql')) + sorted((ROOT/'tests/sql').glob('*.sql'))
        for label, source in [('fixture',fixture)] + [(p.name,p.read_text(encoding='utf-8')) for p in files]:
            if label == '202611140001_binding_replacement.sql':
                source = """insert into auth.users values('00000000-0000-0000-0000-000000000009');
                insert into account_devices_private.bindings(owner_id,device_id,link_key)
                values('00000000-0000-0000-0000-000000000009','WR-0009-0000-0000-0000',repeat('99',32));
                """ + source
            result = subprocess.run(['docker','exec','-i',name,'psql','-h','/tmp','-U','postgres',
                                     '-d','postgres','-X','-v','ON_ERROR_STOP=1'],input=source,text=True,capture_output=True)
            if result.returncode:
                raise RuntimeError(label + ': ' + result.stderr[-3000:])
            print(label + ': passed',flush=True)
        def query(source):
            return subprocess.run(['docker','exec','-i',name,'psql','-h','/tmp','-U','postgres',
                '-d','postgres','-X','-At','-v','ON_ERROR_STOP=1'],input=source,text=True,capture_output=True)

        candidates = []
        for owner, key in [('4','44'*32),('5','55'*32)]:
            uid = '00000000-0000-0000-0000-00000000000' + owner
            result = query(f"""insert into auth.users values('{uid}');
                select set_config('request.jwt.claim.sub','{uid}',false);
                select public.prepare_account_device_claim_v3('WR-0001-0000-0000-0000','CN') as ticket \\gset
                select public.stage_account_device_claim_v3(:'ticket','WR-0001-0000-0000-0000','{key}',
                  encode(extensions.hmac(convert_to('watcher-claim-v3|CN|'||:'ticket'||'|WR-0001-0000-0000-0000|{key}',
                  'UTF8'),decode(repeat('11',32),'hex'),'sha256'),'hex'));
                select public.commit_account_device_claim_v3(:'ticket');
                select json_build_object('ticket',:'ticket','version',
                  public.account_device_claim_state_v3(:'ticket','WR-0001-0000-0000-0000')->>'binding_version');""")
            if result.returncode: raise RuntimeError('Concurrent setup failed: '+result.stderr)
            candidate = json.loads(result.stdout.strip().splitlines()[-1])
            candidate['key'] = key
            candidates.append(candidate)
        def acknowledge(candidate):
            ticket, version, key = candidate['ticket'],candidate['version'],candidate['key']
            return query(f"""begin;
                select public.ack_account_device_claim_v3('{ticket}','WR-0001-0000-0000-0000',
                  encode(extensions.hmac(convert_to('watcher-ack-v3|CN|{ticket}|WR-0001-0000-0000-0000|{key}|{version}',
                  'UTF8'),decode(repeat('11',32),'hex'),'sha256'),'hex'));
                select pg_sleep(0.2);commit;""")
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(acknowledge,candidates))
        if sum(result.returncode == 0 for result in results) != 1 or not any(
                'claim_superseded' in result.stderr for result in results):
            raise RuntimeError('Concurrent owner acknowledgements did not admit exactly one winner')
        winner = candidates[next(i for i,result in enumerate(results) if result.returncode == 0)]
        if acknowledge(winner).returncode:
            raise RuntimeError('Winning acknowledgement is not idempotent')
        print('concurrent replacement ACK fencing and idempotence: passed',flush=True)
        # Polling the same ticket while its ACK commits must never produce an
        # abort/revoke terminal for that successfully acknowledged candidate.
        result = query("""insert into auth.users values('00000000-0000-0000-0000-000000000006');
            select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000006',false);
            select public.prepare_account_device_claim_v3('WR-0001-0000-0000-0000','CN') as ticket \\gset
            select public.stage_account_device_claim_v3(:'ticket','WR-0001-0000-0000-0000',repeat('66',32),
              encode(extensions.hmac(convert_to('watcher-claim-v3|CN|'||:'ticket'||'|WR-0001-0000-0000-0000|'||repeat('66',32),
              'UTF8'),decode(repeat('11',32),'hex'),'sha256'),'hex'));
            select public.commit_account_device_claim_v3(:'ticket');
            select json_build_object('ticket',:'ticket','version',
              public.account_device_claim_state_v3(:'ticket','WR-0001-0000-0000-0000')->>'binding_version');""")
        if result.returncode: raise RuntimeError('ACK/state race setup failed: '+result.stderr)
        candidate = json.loads(result.stdout.strip().splitlines()[-1])
        candidate['key'] = '66'*32
        def poll_candidate():
            statement = "select public.account_device_claim_state_v3('" + candidate['ticket'] + "','WR-0001-0000-0000-0000')->>'state';"
            return query('\n'.join([statement]*24))
        with ThreadPoolExecutor(max_workers=2) as pool:
            ack_future = pool.submit(acknowledge,candidate)
            state_future = pool.submit(poll_candidate)
            ack_result, state_result = ack_future.result(), state_future.result()
        states = state_result.stdout.strip().splitlines()
        if ack_result.returncode or state_result.returncode or len(states) != 24 or any(
                state not in ('committed','active') for state in states):
            raise RuntimeError('Concurrent successful ACK was misclassified as an aborted claim')
        print('concurrent ACK/state terminal classification: passed',flush=True)

    finally:
        if created:
            subprocess.run(['docker','rm','-f',name],check=True,stdout=subprocess.DEVNULL)

if __name__ == '__main__':
    main()
