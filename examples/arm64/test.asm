mov    w0, 0x5678
mov    w1, 0x1234
bfi    w0, w1, 16, 16
mov    x1, x0
ubfx   x0, x1, 8, 8
ubfiz  x0, x1, 8, 8
bfxil  x0, x1, 0, 8
bfxil  x0, xzr, 0, 8
