"""Validate the consultation-only ZIP before deploying GitHub Pages.

This file is public deployment plumbing, not a financial engine. Its explicit
allowlist prevents accidentally deploying AWW-reprise.zip or aww-source.zip.
Hashes detect incomplete transfers; they are not a digital signature.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import struct
import zipfile
import zlib

SHELL = {'index.html', 'viewer.js', 'viewer.css', 'navigation.js', 'sw.js',
         'catalog.json', 'manifest.webmanifest', 'icon-192.png', 'icon-512.png',
         'apple-touch-icon.png', '.nojekyll'}
FORBIDDEN = re.compile(rb'AWW_STRATEGY|AWW_PROPHET|AWW_EARLY|AWW_DATA|'
                       rb'function\s+indexSignals|function\s+cycleMetrics|'
                       rb'function\s+dcaIndications|createStepper|metricsProvider|'
                       rb'sellMemory|buyMemory|releaseAfterFinancialStop|sourceMappingURL|'
                       rb'github_pat_[A-Za-z0-9_]{20}|gh[pousr]_[A-Za-z0-9]{20}|'
                       rb'-----BEGIN .*PRIVATE KEY-----')


def validate_nq_raster(tile):
    if set(tile) != {'from', 'count', 'low', 'high', 'image'}:
        raise ValueError('Métadonnées raster NQ incorrectes')
    if not 0 < tile['count'] <= 96 or not 0 < tile['low'] < tile['high'] or tile['low'] % 500 or tile['high'] % 500:
        raise ValueError('Dimensions raster NQ incorrectes')
    if len(tile['image']) >= 100_000:
        raise ValueError('Tuile NQ trop grande')
    png = base64.b64decode(tile['image'], validate=True)
    if not png.startswith(bytes.fromhex('89504e470d0a1a0a')):
        raise ValueError('Image PNG NQ attendue')
    chunks = {}
    offset = 8
    while offset < len(png):
        length, chunk = struct.unpack_from('>I4s', png, offset)
        end = offset + 12 + length
        if end > len(png) or chunk in chunks:
            raise ValueError('Image NQ incomplète ou dupliquée')
        chunks[chunk] = png[offset + 8:end - 4]
        if struct.unpack_from('>I', png, end - 4)[0] != zlib.crc32(png[offset + 4:end - 4]):
            raise ValueError('Somme de contrôle PNG NQ incorrecte')
        offset = end
    if list(chunks) != [b'IHDR', b'PLTE', b'tRNS', b'IDAT', b'IEND']:
        raise ValueError('Image NQ avec données auxiliaires interdites')
    width = 6 * tile['count']
    if chunks[b'IHDR'] != struct.pack('>IIBBBBB', width, 512, 8, 3, 0, 0, 0):
        raise ValueError('Format raster NQ incorrect')
    if len(chunks[b'PLTE']) != 21 or chunks[b'tRNS'] != b'\x00' or chunks[b'IEND']:
        raise ValueError('Palette raster NQ incorrecte')
    size = (width + 1) * 512
    decoder = zlib.decompressobj()
    pixels = decoder.decompress(chunks[b'IDAT'], size + 1)
    if len(pixels) != size or not decoder.eof or decoder.unused_data or max(pixels) > 6 or any(pixels[::width + 1]):
        raise ValueError('Image NQ avec pixels invalides')


def validate_nq_view(view, files):
    if view.get('tf') != 'h4' or view.get('index') != 'ndx':
        return
    price = json.loads(files[view['panels'][0]])
    cutoff = price.get('nqPrefixCutoff')
    if not cutoff:
        if view['from'] < '2023-01-01' or 'nqRaster' in price:
            raise ValueError('La période NQ exige des images rendues')
        return
    if cutoff != '2023-09-04T07:00:00Z' or not price.get('nqRaster'):
        raise ValueError('Raccord NQ incorrect')
    allowed = {'id', 'title', 'kind', 'series', 'markers', 'segments', 'zones', 'legend',
               'candles', 'cursorPeak', 'cursorPeaks', 'ytd', 'drawdowns', 'readouts',
               'h4Splice', 'h4Lines', 'regimes', 'nqPrefixCutoff', 'nqRaster', 'referenceMark'}
    if set(price) - allowed or price['candles'][0][0] != cutoff:
        raise ValueError('Champ ou cotation NQ numérique interdit')
    tick = price.get('referenceMark')
    if tick is not None:
        candles = price['candles']
        if (len(candles) < 31 or set(tick) != {'date', 'value'} or
                tick['date'] != candles[-1][0] or tick['value'] != candles[-31][4]):
            raise ValueError('Repère H4 non confirmé par les bougies CFD publiques')
    prices = ([r[0] for r in price['candles']] + [r[0] for r in price['cursorPeaks']] +
              [r['date'] for r in price['markers']] + [r['date'] for r in price['drawdowns']] +
              [r[0] for line in price['h4Lines'] for r in [*line['ends'], *line['dots'], line['labelAt']]])
    if any(date < cutoff for date in prices):
        raise ValueError('Prix NQ numériques interdits')
    entries = {mark['label'][3:] for mark in price['markers'] if mark['label'].startswith('EX #')}
    if any(mark['label'][2:] not in entries for mark in price['markers'] if mark['label'].startswith('× #')):
        raise ValueError('Prix de sortie d’une position ouverte sur NQ interdit')
    if price['cursorPeak'] != max(r[2] for r in price['candles']):
        raise ValueError('Sommet de prix NQ numérique interdit')
    ma_boundary = price['candles'][29][0]
    if any(r[0] < (ma_boundary if s['key'] == 'ma' else cutoff) for s in price['series'] for r in s['points']):
        raise ValueError('Cours ou moyennes NQ numériques interdits')
    calendar = json.loads(files[view['calendar']])
    index = 0
    if calendar[0] not in ('2021-01-03T20:00:00Z', '2022-01-02T20:00:00Z'):
        raise ValueError('Début du calendrier NQ incorrect')
    for tile in price['nqRaster']:
        validate_nq_raster(tile)
        if tile['from'] != calendar[index]:
            raise ValueError('Calendrier NQ et image non alignés')
        index += tile['count']
    if calendar[index] != cutoff or index + len(price['candles']) != view['bars']:
        raise ValueError('Couverture NQ discontinue')
    panels = [p for name in view['panels'][1:] if (p := json.loads(files[name]))['id'] in {'position', 'equity'}]
    if {p['id'] for p in panels} != {'position', 'equity'} or any(p.get('nqPrefixCutoff') != cutoff for p in panels):
        raise ValueError('Raccord NQ incomplet dans les panneaux')
    position = next(p for p in panels if p['id'] == 'position')
    if any(value not in (None, -100, -50, 0, 50, 100) for series in position['series'] for _, value in series['points']):
        raise ValueError('Série de position H4 invalide')
    equity = next(p for p in panels if p['id'] == 'equity')
    exact_from = equity.get('nqExactCapitalFrom')
    if not exact_from or not cutoff <= exact_from <= price['h4Splice'] or exact_from not in calendar:
        raise ValueError('Fin du capital quotidien NQ incorrecte')
    for series in equity['series']:
        historical = [(d, value) for d, value in series['points'] if d < exact_from]
        days = [d[:10] for d, _ in historical[1:]]
        if not historical or len(days) != len(set(days)) or any(value is not None and float(format(value, '.2g')) != value for _, value in historical):
            raise ValueError('Capital NQ avant le raccord : points quotidiens arrondis uniquement')
    if any(r[0] < exact_from for r in equity['drawdownSeries']) or any(p['from'] < exact_from for p in equity['h4Periods']):
        raise ValueError('Détail chiffré non prévu dans le préfixe NQ')


def validate(archive):
    with zipfile.ZipFile(archive) as bundle:
        names = bundle.namelist()
        if len(names) != len(set(names)) or len(names) > 1000:
            raise ValueError('Archive dupliquée ou trop grande')
        if sum(i.file_size for i in bundle.infolist()) > 200_000_000:
            raise ValueError('Archive décompressée trop grande')
        for name in names:
            if name not in SHELL | {'manifest-public.json'} and not re.fullmatch(r'data/[a-f0-9]{64}\.json', name):
                raise ValueError('Fichier interdit : ' + name)
        files = {name: bundle.read(name) for name in names}
    manifest = json.loads(files['manifest-public.json'])
    if set(manifest) != {'schemaVersion', 'files'} or manifest['schemaVersion'] != 1 or set(files) != set(manifest['files']) | {'manifest-public.json'}:
        raise ValueError('Manifeste incomplet')
    if FORBIDDEN.search(files['manifest-public.json']):
        raise ValueError('Manifeste privé interdit')
    if not SHELL <= set(files):
        raise ValueError('Lecteur incomplet')
    for name, entry in manifest['files'].items():
        if set(entry) != {'bytes', 'sha256'}:
            raise ValueError('Entrée de manifeste incorrecte')
        raw = files[name]
        digest = hashlib.sha256(raw).hexdigest()
        if len(raw) != entry['bytes'] or digest != entry['sha256']:
            raise ValueError('Empreinte incorrecte : ' + name)
        if not name.endswith('.png') and FORBIDDEN.search(raw):
            raise ValueError('Contenu privé interdit : ' + name)
        if name.startswith('data/') and name != 'data/' + digest + '.json':
            raise ValueError('Nom de données incorrect')
    catalog = json.loads(files['catalog.json'])
    # The two optional Nasdaq H4 result sets use identical public panel schemas.
    if catalog['schemaVersion'] != 1 or len(catalog['views']) not in (15, 21, 22, 26):
        raise ValueError('Catalogue incorrect')
    has_regime = any(view.get('scenario') == 'aww' or view.get('id') == 'ndx-h4-aww'
                     for view in catalog['views'])
    if len(catalog['views']) in (22, 26) or has_regime:
        expected = {f'{index}-{tf}-{scenario}' for index in ('ndx', 'spx', 'dow')
                    for tf in ('daily', 'weekly') for scenario in ('sys1', 'classic')}
        expected |= {f'{index}-h4-{scenario}' for index in ('ndx', 'spx', 'dow')
                     for scenario in ('v', 'r', 'vr')}
        expected.add('ndx-h4-aww')
        if len(catalog['views']) == 26:
            expected |= {f'ndx-h4-{s}-alt' for s in ('v', 'r', 'vr', 'aww')}
        ids = [view.get('id') for view in catalog['views']]
        if set(ids) != expected or len(ids) != len(set(ids)):
            raise ValueError('Vues publiques incorrectes')
        for view in catalog['views']:
            identity = '-'.join(str(view.get(key, '')) for key in ('index', 'tf', 'scenario'))
            if 'variant' in view:
                if view['variant'] is not True or view['index'] != 'ndx' or view['tf'] != 'h4':
                    raise ValueError('Variante publique incorrecte')
                identity += '-alt'
            if view['id'] != identity:
                raise ValueError('Vue publique incorrecte')
    for view in catalog['views']:
        for name in [view['calendar'], *view['panels']]:
            if not re.fullmatch(r'data/[a-f0-9]{64}\.json', name) or name not in files:
                raise ValueError('Résultat manquant')
        validate_nq_view(view, files)
    return files


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('archive')
    parser.add_argument('--extract', type=Path)
    args = parser.parse_args()
    files = validate(args.archive)
    if args.extract:
        target = args.extract.resolve()
        if target.exists() and any(target.iterdir()):
            raise ValueError('Choisir un dossier de sortie vide')
        for name, raw in files.items():
            dest = target / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(raw)
    print(json.dumps({'files': len(files), 'bytes': sum(map(len, files.values())), 'valid': True}))


if __name__ == '__main__':
    main()
