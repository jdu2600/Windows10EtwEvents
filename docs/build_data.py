"""Bundle the manifest/, mof/ and unknown/ TSVs into docs/data/ for the GitHub Pages event browser.

Every Windows version in the git history gets its own docs/data/<version>.json, using the last commit
whose version.txt names that version. The working tree is used for the current version.
docs/data/versions.json lists them, newest first.

Usage: python docs/build_data.py [repo_root] [out_dir]
"""
import hashlib
import json
import os
import re
import subprocess
import sys

root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
out_dir = sys.argv[2] if len(sys.argv) > 2 else os.path.join(root, 'docs', 'data')
KINDS = ('manifest', 'mof', 'unknown')


def git(*args):
    return subprocess.run(['git', '-C', root, *args], capture_output=True, check=True).stdout.decode('utf-8')


class WorkingTree:
    ref = 'main'

    def files(self):
        return sorted((f'{kind}/{name}' for kind in KINDS if os.path.isdir(os.path.join(root, kind))
                       for name in os.listdir(os.path.join(root, kind)) if name.endswith('.tsv')), key=str.lower)

    def read(self, paths):
        for path in paths:
            with open(os.path.join(root, path), encoding='utf-8') as f:
                yield f.read()

    def version(self):
        with open(os.path.join(root, 'version.txt'), encoding='utf-8') as f:
            return f.read().strip()


class Commit:
    def __init__(self, ref):
        self.ref = ref

    def files(self):
        # -z: unquoted paths, so names with non-ASCII characters aren't dropped
        return sorted((f for f in git('ls-tree', '-r', '-z', '--name-only', self.ref).split('\0')
                       if f.split('/')[0] in KINDS and f.endswith('.tsv')), key=str.lower)

    def read(self, paths):
        # one git process for all of this commit's files
        proc = subprocess.run(['git', '-C', root, 'cat-file', '--batch'], capture_output=True, check=True,
                              input=''.join(f'{self.ref}:{p}\n' for p in paths).encode('utf-8')).stdout
        pos = 0
        for _ in paths:
            header_end = proc.index(b'\n', pos)
            size = int(proc[pos:header_end].split()[2])
            yield proc[header_end + 1:header_end + 1 + size].decode('utf-8')
            pos = header_end + 1 + size + 1

    def version(self):
        return git('show', f'{self.ref}:version.txt').strip()


def build(source):
    # annotate() appends: providers +[since]; events +[since, [[field index, since], ...] or 0]
    providers = []  # [name, kind, tsv file name, event count]
    manifest = []  # [provider index, id, version, event(fields), opcode, keywords, task, level, channel, message]
    mof = []  # [provider index, id, version, event(fields), event_type, category, description]
    paths = source.files()
    for path, text in zip(paths, source.read(paths)):
        kind, name = path.split('/', 1)
        rows = [line.split('\t') for line in text.splitlines()[1:] if line]
        providers.append([rows[0][0] if rows else name[:-4], kind, name, 0 if kind == 'unknown' else len(rows)])
        p = len(providers) - 1
        for c in rows:
            if kind == 'manifest':
                manifest.append([p, int(c[1]), int(c[2])] + c[3:10])
            elif kind == 'mof':
                mof.append([p, int(c[2]), int(c[3]), c[4], c[5], c[1], c[6]])
    return {'version': source.version(), 'ref': source.ref, 'providers': providers, 'manifest': manifest, 'mof': mof}


def short_name(version):
    # "Windows 10 Enterprise 21H1 19043.928 (...)" -> ("Windows 10 21H1", "10-21H1")
    # "Windows 10 Enterprise LTSC 2019 (...)"      -> ("Windows 10 2019", "10-2019")
    m = re.match(r'Windows (\d+)\b.*?\b(\d\dH\d|\d{4})\b', version)
    if not m:
        return version, re.sub(r'\W+', '_', version).strip('_')
    return f'Windows {m.group(1)} {m.group(2)}', f'{m.group(1)}-{m.group(2)}'


def field_names(sig):
    # "ProcessStart(UInt32 ProcessID, UnicodeString ImageName)" -> ["ProcessID", "ImageName"]
    m = re.match(r'^([^(]*)\((.*)\)$', sig)
    return [f[f.rfind(' ') + 1:] for f in m.group(2).split(', ')] if m and m.group(2) else []


# "git blame" for the schemas: the first Windows version (slug) each thing was seen in, oldest version first
first_seen = {}
order = {}  # slug -> age rank


def annotate(data, slug):
    """Append since/field-since to every event row, and since to every provider, using first_seen."""
    order[slug] = len(order)
    for prov in data['providers']:
        prov.append(first_seen.setdefault(('provider', prov[1], prov[0]), slug))
    for kind, rows, cat in (('manifest', data['manifest'], None), ('mof', data['mof'], 5)):
        for r in rows:
            family = (kind, data['providers'][r[0]][0], r[cat] if cat else '', r[1])
            event_since = first_seen.setdefault(family + (r[2],), slug)  # this event version
            family_since = first_seen.setdefault(family, slug)  # any version of this event id
            # fields only get their own "since" when they arrived after the event id itself
            later = []
            for i, name in enumerate(field_names(r[3])):
                field_since = first_seen.setdefault(family + ('field', name), slug)
                if order[field_since] > order[family_since]:
                    later.append([i, field_since])
            r.extend([event_since, later or 0])


def snapshots():
    """Yield (source) for every Windows version, oldest first, ending with the working tree."""
    current = WorkingTree().version()
    try:
        commits = git('log', '--reverse', '--format=%H', '--first-parent', 'HEAD').split()
    except (OSError, subprocess.CalledProcessError):
        commits = []  # not a git checkout: just the working tree
    last = {}  # version.txt contents -> last commit carrying it (so later fix-ups are included)
    for commit in commits:
        try:
            last[Commit(commit).version()] = commit
        except subprocess.CalledProcessError:
            pass  # no version.txt yet
    for v, commit in last.items():  # dicts keep first-seen order, i.e. oldest version first
        if v != current:
            yield Commit(commit)
    yield WorkingTree()


os.makedirs(out_dir, exist_ok=True)
index = []
for source in snapshots():
    data = build(source)
    label, slug = short_name(data['version'])
    if any(v['id'] == slug for v in index):  # e.g. two editions of the same release
        n = sum(v['id'].startswith(slug) for v in index) + 1
        label, slug = f'{label} ({n})', f'{slug}-{n}'
    annotate(data, slug)
    body = json.dumps(data, separators=(',', ':')).encode('utf-8')
    with open(os.path.join(out_dir, slug + '.json'), 'wb') as f:
        f.write(body)
    events = len(data['manifest']) + len(data['mof'])
    # hash: the page fetches data/<file>?h=<hash>, so a rebuilt bundle is never served from a stale cache
    index.append({'id': slug, 'label': label, 'build': data['version'], 'ref': data['ref'], 'file': slug + '.json',
                  'hash': hashlib.sha1(body).hexdigest()[:12], 'events': events})
    print(f'{label:18} {source.ref[:8]:8} {events:7,} events, {len(data["providers"]):5,} providers')

with open(os.path.join(out_dir, 'versions.json'), 'w', encoding='utf-8', newline='\n') as f:
    json.dump(index[::-1], f, indent=1)
