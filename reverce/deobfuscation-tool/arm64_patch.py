"""Minimal checked AArch64 direct branch encoders."""

CONDITIONS = {'eq': 0, 'ne': 1, 'cs': 2, 'hs': 2, 'cc': 3, 'lo': 3,
              'mi': 4, 'pl': 5, 'vs': 6, 'vc': 7, 'hi': 8, 'ls': 9,
              'ge': 10, 'lt': 11, 'gt': 12, 'le': 13}


def _offset(site, target, bits):
    if site < 0 or target < 0 or site % 4 or target % 4:
        raise ValueError('unaligned or negative address')
    delta = (target - site) // 4
    if not -(1 << (bits - 1)) <= delta < (1 << (bits - 1)):
        raise ValueError('branch out of range')
    return delta & ((1 << bits) - 1)


def encode_b(site, target):
    return (0x14000000 | _offset(site, target, 26)).to_bytes(4, 'little').hex()


def encode_b_cond(site, target, condition):
    if condition not in CONDITIONS:
        raise ValueError('unsupported condition')
    return (0x54000000 | (_offset(site, target, 19) << 5) | CONDITIONS[condition]).to_bytes(4, 'little').hex()
