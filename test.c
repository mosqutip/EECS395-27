int a, b, d, *p;

int f (int x) {
  return a + x;
}

int main (int c, char **v) {
  p = &b;
  a = 1;
  *p = 2;
  d = 3;
  c = f(b);
}
