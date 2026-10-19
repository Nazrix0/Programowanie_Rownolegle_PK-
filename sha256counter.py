import argparse, hashlib, os, shutil, sys, threading, time
from concurrent.futures import ThreadPoolExecutor

CHUNK = 1024 * 1024


def fmt_time(sec):
    sec = int(max(sec, 0))
    return f"{sec // 3600:02d}:{sec % 3600 // 60:02d}:{sec % 60:02d}"


def collect(paths):
    out = []
    for p in paths:
        if os.path.isdir(p):
            out += sorted(os.path.join(r, f) for r, _, fs in os.walk(p) for f in fs)
        else:
            out.append(p)
    return out


def main():
    ap = argparse.ArgumentParser(description="SHA-256 plików z paskiem postępu")
    ap.add_argument("paths", nargs="+", help="pliki lub foldery")
    ap.add_argument("-j", "--threads", type=int, default=os.cpu_count() or 4)
    ap.add_argument("-o", "--output", help="zapisz wyniki do pliku (format sha256sum)")
    a = ap.parse_args()

    files = collect(a.paths)
    if not files:
        sys.exit("Brak plików.")
    total = sum(os.path.getsize(p) for p in files)
    hashes = [""] * len(files)
    state = {"done": 0, "files": 0}
    lock = threading.Lock()

    def work(i):
        h = hashlib.sha256()
        with open(files[i], "rb") as f:
            while chunk := f.read(CHUNK):
                h.update(chunk)
                with lock:
                    state["done"] += len(chunk)
        hashes[i] = h.hexdigest()
        with lock:
            state["files"] += 1

    def draw(final=False):
        with lock:
            done, fd = state["done"], state["files"]
        el = time.time() - t0
        frac = done / total if total else fd / len(files)
        eta = el / frac - el if frac > 0 else 0
        speed = done / el / 1e6 if el > 0 else 0
        info = (f" {frac * 100:5.1f}% | {fd}/{len(files)} plików | {speed:6.1f} MB/s"
                f" | pozostało {fmt_time(eta)} | koniec ok. "
                f"{time.strftime('%H:%M:%S', time.localtime(time.time() + eta))}")
        width = max(shutil.get_terminal_size().columns - len(info) - 3, 10)
        filled = int(width * frac)
        line = f"[{'#' * filled}{'-' * (width - filled)}]{info}"
        sys.stderr.write("\r" + line + ("\n" if final else ""))
        sys.stderr.flush()

    t0 = time.time()
    ex = ThreadPoolExecutor(a.threads)
    futs = [ex.submit(work, i) for i in range(len(files))]
    try:
        while not all(f.done() for f in futs):
            draw()
            time.sleep(0.1)
    except KeyboardInterrupt:
        ex.shutdown(wait=False, cancel_futures=True)
        sys.stderr.write("\nPrzerwano.\n")
        os._exit(1)
    for f in futs:
        f.result()
    ex.shutdown()
    draw(final=True)

    lines = [f"{h}  {p}" for h, p in zip(hashes, files)]
    print("\n".join(lines))
    print(f"\nGotowe: {len(files)} plików, {total / 1e6:.1f} MB w {time.time() - t0:.2f} s "
          f"({a.threads} wątków).", file=sys.stderr)
    if a.output:
        with open(a.output, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
