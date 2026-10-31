"""Makes the light (480p) copy of every academy lesson that doesn't have one yet.

Runs inside GitHub Actions only: it signs every request with the run's GitHub OIDC token,
which the academy API checks (repo + main branch) before letting it read or write videos.
"""
import json, os, subprocess, sys, time, urllib.request

API = 'https://academy.marketingmiddleeast.com/api/tc'
PART = 8 * 1024 * 1024


def token():
    req = urllib.request.Request(os.environ['ACTIONS_ID_TOKEN_REQUEST_URL'] + '&audience=mme-academy-transcode',
                                 headers={'Authorization': 'bearer ' + os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']})
    return json.load(urllib.request.urlopen(req, timeout=30))['value']


def call(method, path, data=None, ctype='application/json', timeout=300):
    for attempt in range(5):
        try:
            req = urllib.request.Request(API + path, data=data, method=method,
                                         headers={'Authorization': 'Bearer ' + token(), 'Content-Type': ctype,
                                                  'User-Agent': 'mme-transcode'})
            return urllib.request.urlopen(req, timeout=timeout)
        except Exception as e:  # noqa: BLE001 - retry any network hiccup
            print(f'  retry {attempt + 1} {method} {path}: {e}', flush=True)
            time.sleep(5 * (attempt + 1))
    sys.exit(f'failed: {method} {path}')


def download(lid, dst):
    r = call('GET', f'/src/{lid}', timeout=600)
    key, total, got = r.headers.get('x-src-key'), int(r.headers.get('content-length') or 0), 0
    with open(dst, 'wb') as f:
        while chunk := r.read(1 << 20):
            f.write(chunk); got += len(chunk)
    if total and got != total:
        raise IOError(f'short download {got}/{total}')
    return key


def convert(src, dst):
    vf = "scale='if(gt(iw,ih),-2,min(480,iw))':'if(gt(iw,ih),min(480,ih),-2)'"
    subprocess.run(['ffmpeg', '-v', 'error', '-y', '-i', src, '-vf', vf, '-c:v', 'libx264', '-preset', 'veryfast',
                    '-crf', '27', '-maxrate', '650k', '-bufsize', '1300k', '-profile:v', 'main', '-pix_fmt', 'yuv420p',
                    '-c:a', 'aac', '-b:a', '64k', '-ac', '2', '-movflags', '+faststart', dst], check=True)


def upload(lid, path, src_key):
    up = json.load(call('POST', f'/start/{lid}', b'{}'))
    parts, n = [], 0
    with open(path, 'rb') as f:
        while data := f.read(PART):
            n += 1
            q = f"?key={up['key']}&uploadId={urllib.parse.quote(up['uploadId'])}&n={n}"
            parts.append(json.load(call('PUT', '/part' + q, data, 'application/octet-stream')))
    body = json.dumps({'key': up['key'], 'uploadId': up['uploadId'], 'parts': parts, 'src_key': src_key}).encode()
    return json.load(call('POST', f'/done/{lid}', body))


import urllib.parse  # noqa: E402

jobs = json.load(call('GET', '/jobs'))['jobs']
print(f'{len(jobs)} lesson(s) need a light copy', flush=True)
for j in jobs:
    t0 = time.time()
    print(f"#{j['id']} {j['title']} ({(j['video_size'] or 0) / 1e6:.0f} MB)", flush=True)
    try:
        key = download(j['id'], 'src.mp4')
        convert('src.mp4', 'low.mp4')
        res = upload(j['id'], 'low.mp4', key)
        print(f"  -> {os.path.getsize('low.mp4') / 1e6:.0f} MB, {res}, {time.time() - t0:.0f}s", flush=True)
    except Exception as e:  # noqa: BLE001 - one bad lesson must not stop the rest
        print(f'  FAILED: {e}', flush=True)
    finally:
        for f in ('src.mp4', 'low.mp4'):
            if os.path.exists(f):
                os.remove(f)
