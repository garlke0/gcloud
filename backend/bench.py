import time
from argon2 import PasswordHasher

def bench(m, t, p):
    ph = PasswordHasher(memory_cost=m, time_cost=t, parallelism=p)
    ph.hash("warmup")
    start = time.perf_counter()
    ph.hash("hello")
    ms = (time.perf_counter() - start) * 1000
    print(f"m={m:6}  t={t}  p={p}  ->  {ms:.0f} ms")

bench(262144, 3, 4)
bench(262144, 4, 4)
bench(131072, 4, 4)
bench(196608, 3, 4)