"""Small source corpus for PegRex language-model and call-chain examples."""


def clamp_nonnegative(value):
    if value < 0:
        return 0
    return value


def normalize_then_scale(value, factor):
    return clamp_nonnegative(value) * factor
