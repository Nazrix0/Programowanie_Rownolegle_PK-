import os
import hashlib
import random

BASE_DIR = "dataset"
MANIFEST_FILE = "reference_manifest.sha256"

def calculate_sha256(filepath):
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()

def make_file(path, size_bytes, pattern=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        if pattern:
            # Powtarzalny wzorzec (przydatne do weryfikacji deduplikacji blokowej)
            repeats = size_bytes // len(pattern)
            f.write(pattern * repeats)
            f.write(pattern[:size_bytes % len(pattern)])
        else:
            # Deterministyczne pseudolosowe dane (ustawione ziarno)
            f.write(random.randbytes(size_bytes))

def build_dataset():
    random.seed(42)  # Zapewnia powtarzalność generowanych danych u każdego!
    
    # 1. Edge-cases
    make_file(f"{BASE_DIR}/edge_cases/empty.bin", 0)
    make_file(f"{BASE_DIR}/edge_cases/single_byte.bin", 1)
    
    # 2. Baza pod deduplikację (pliki identyczne o różnych nazwach)
    sample_content = b"DEDUP_TEST_STRING_ABCD_1234_" * 100
    make_file(f"{BASE_DIR}/dedup/original_file.txt", len(sample_content), sample_content)
    make_file(f"{BASE_DIR}/dedup/exact_copy_1.txt", len(sample_content), sample_content)
    make_file(f"{BASE_DIR}/dedup/nested/exact_copy_2.txt", len(sample_content), sample_content)

    # 3. Zbiór pod Merkle Tree (dużo małych plików w strukturze drzewiastej)
    for i in range(1, 201):
        folder = f"batch_{i % 5}"
        make_file(f"{BASE_DIR}/merkle_leafs/{folder}/node_{i:04d}.dat", random.randint(512, 4096))

    # 4. Pliki średnie/duże do testów wydajnościowych strumieniowania
    make_file(f"{BASE_DIR}/performance/medium_10mb.bin", 10 * 1024 * 1024)
    make_file(f"{BASE_DIR}/performance/large_50mb.bin", 50 * 1024 * 1024)

    # Generowanie referencyjnego manifestu SHA-256
    manifest_entries = []
    for root, _, files in os.walk(BASE_DIR):
        for f in files:
            full_path = os.path.join(root, f)
            rel_path = os.path.relpath(full_path, BASE_DIR).replace("\\", "/")
            h = calculate_sha256(full_path)
            manifest_entries.append((h, rel_path))

    # Sortowanie po ścieżce (kluczowe dla determinizmu w drzewie Merkle'a)
    manifest_entries.sort(key=lambda x: x[1])

    with open(MANIFEST_FILE, "w", encoding="utf-8") as out:
        for h, rel_path in manifest_entries:
            out.write(f"{h}  {rel_path}\n")

    print(f"Wygenerowano {len(manifest_entries)} plików w katalogu '{BASE_DIR}'.")
    print(f"Plik weryfikacyjny zapisany w: {MANIFEST_FILE}")

if __name__ == "__main__":
    build_dataset()