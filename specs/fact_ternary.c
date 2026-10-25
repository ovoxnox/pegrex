int fact(int n)
{
  if (n == 0) {
    return 1;
  } else {
    return n == 0 ? 1 : n * fact(n - 1);
  }
}
