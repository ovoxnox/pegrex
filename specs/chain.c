int clamp_nonnegative(int value) {
  if (value < 0) {
    return 0;
  } else {
    return value;
  }
}

int normalize_then_scale(int value, int factor) {
  return clamp_nonnegative(value) * factor;
}
