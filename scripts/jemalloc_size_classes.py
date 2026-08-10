#!/usr/bin/env python3
"""Diff jemalloc live bytes per size class between two `stats_print` dumps.

The aggregate counters in `alloc_stats.rs` only prove that a leak exists.
This names it: the size class that grows across two dumps taken while the
leak accumulates tells you how big the leaked object is, and the object
delta tells you how many of them there are -- which is usually enough to
identify the allocation site by inspection.

Produce the dumps by running the node with
    SHOES_ALLOCATOR_STATS_DUMP_INTERVAL_SECS=1800
then:
    docker logs <container> 2>&1 | grep 'jemalloc stats dump' > dumps.log
    ./jemalloc_size_classes.py dumps.log            # first vs last
    ./jemalloc_size_classes.py dumps.log 1 3        # pick dumps by index

Compare only dumps taken well after startup: the first minutes are warm-up,
not leak. Traffic noise on a busy node is several MB per hour, so a window
shorter than a few hours cannot resolve a slow leak.
"""
import json
import re
import sys

# jemalloc x86-64 (lg_quantum=4, lg_page=12) small bin size classes, in bin order.
# The dumps are written with skip_constants, so the sizes are not in the JSON.
SMALL = [8, 16, 32, 48, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 448,
         512, 640, 768, 896, 1024, 1280, 1536, 1792, 2048, 2560, 3072, 3584,
         4096, 5120, 6144, 7168, 8192, 10240, 12288, 14336]


def large_classes(count):
    """Large extent classes: groups of four, base doubling from 16 KiB."""
    out = []
    base = 16384
    while len(out) < count:
        for step in range(4):
            out.append(base + step * (base // 4))
            if len(out) == count:
                break
        base *= 2
    return out


def load(path):
    dumps = []
    for line in open(path):
        marker = line.find('jemalloc stats dump: ')
        if marker < 0:
            continue
        stamp = re.search(r'\[(\d{4}-\d\d-\d\dT[\d:.]+)', line)
        dumps.append((stamp.group(1) if stamp else '?',
                      json.loads(line[marker + len('jemalloc stats dump: '):])))
    return dumps


def live_bytes_by_size(dump):
    merged = dump['jemalloc']['stats.arenas']['merged']
    out = {}
    for index, entry in enumerate(merged['bins']):
        size = SMALL[index]
        out[size] = out.get(size, 0) + entry['curregs'] * size
    classes = large_classes(len(merged['lextents']))
    for index, entry in enumerate(merged['lextents']):
        size = classes[index]
        out[size] = out.get(size, 0) + entry['curlextents'] * size
    return out


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    dumps = load(sys.argv[1])
    if len(dumps) < 2:
        sys.exit(f'need at least 2 dumps, found {len(dumps)}')
    allocated = lambda d: d['jemalloc']['stats']['allocated']
    print('allocated: ' + ' -> '.join(
        f'{allocated(d)/2**20:.1f}MB@{t[11:16]}' for t, d in dumps))

    first = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    last = int(sys.argv[3]) if len(sys.argv) > 3 else len(dumps) - 1
    start, end = dumps[first], dumps[last]
    before, after = live_bytes_by_size(start[1]), live_bytes_by_size(end[1])
    delta = (allocated(end[1]) - allocated(start[1])) / 2**20
    print(f'\nwindow {start[0][11:19]} -> {end[0][11:19]}  ({delta:+.1f} MB)')

    rows = sorted(((after.get(s, 0) - before.get(s, 0), s,
                    before.get(s, 0), after.get(s, 0))
                   for s in set(before) | set(after)), reverse=True)
    print(f"{'size':>9} {'delta_MB':>9} {'from_MB':>8} {'to_MB':>8} {'d_objs':>9}")
    for diff, size, was, now in rows[:12]:
        if diff <= 0:
            break
        print(f'{size:>9} {diff/2**20:>+9.2f} {was/2**20:>8.2f} {now/2**20:>8.2f} {diff//size:>+9}')
    print('  --- largest decreases ---')
    for diff, size, was, now in rows[-4:]:
        print(f'{size:>9} {diff/2**20:>+9.2f} {was/2**20:>8.2f} {now/2**20:>8.2f} {diff//size:>+9}')


if __name__ == '__main__':
    main()
