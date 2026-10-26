// SHA-256 dla zbioru plików - OpenMP (pamięć współdzielona).
// Każdy plik jest liczony przez jeden z wątków zespołu; liczbę wątków wybiera się opcją -p (1..16).
#include <omp.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "sha256.hpp"

namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;

static const int MAX_THREADS = 16;

static std::atomic<unsigned long long> g_done_bytes{0};
static std::atomic<size_t> g_done_files{0};
static unsigned long long g_total_bytes = 0;
static size_t g_total_files = 0;
static Clock::time_point g_start;
static Clock::time_point g_last_draw;

static std::string fmt_time(double s) {
    int t = (int)std::max(s, 0.0);
    char b[16];
    std::snprintf(b, sizeof b, "%02d:%02d:%02d", t / 3600, t % 3600 / 60, t % 60);
    return b;
}

static void draw(bool force) {
#pragma omp critical(draw_progress)
    {
        auto now = Clock::now();
        if (force || now - g_last_draw >= std::chrono::milliseconds(100)) {
            g_last_draw = now;
            double el = std::chrono::duration<double>(now - g_start).count();
            unsigned long long d = g_done_bytes;
            size_t f = g_done_files;
            double frac = g_total_bytes ? (double)d / g_total_bytes
                                        : (double)f / (g_total_files ? g_total_files : 1);
            if (force) frac = 1.0;
            double eta = frac > 0 ? el / frac - el : 0;
            double mbs = el > 0 ? d / el / 1e6 : 0;
            const int W = 30;
            int fill = (int)(W * frac);
            std::fprintf(stderr, "\r[%s%s] %5.1f%% | %zu/%zu plików | %7.1f MB/s | pozostało %s   ",
                         std::string(fill, '#').c_str(), std::string(W - fill, '-').c_str(),
                         frac * 100, f, g_total_files, mbs, fmt_time(eta).c_str());
            if (force) std::fprintf(stderr, "\n");
            std::fflush(stderr);
        }
    }
}

// SHA-256 jednego pliku - bez stanu współdzielonego, więc bezpieczne dla wielu wątków.
static std::string sha256_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) return "BLAD_ODCZYTU";
    Sha256 sha;
    std::vector<char> buf(1 << 20);
    while (in) {
        in.read(buf.data(), (std::streamsize)buf.size());
        std::streamsize n = in.gcount();
        if (n > 0) {
            sha.update(reinterpret_cast<const uint8_t*>(buf.data()), (size_t)n);
            g_done_bytes += (unsigned long long)n;
            draw(false);
        }
    }
    return Sha256::to_hex(sha.finish());
}

static void usage(const char* prog) {
    std::cerr << "Użycie: " << prog << " [-p wątki(1-" << MAX_THREADS << ")] [-v] [-o plik] plik_lub_folder...\n"
              << "  -p N   liczba wątków OpenMP (domyślnie: liczba rdzeni, max " << MAX_THREADS << ")\n"
              << "  -v     pokaż, który wątek policzył który plik\n"
              << "  -o F   zapisz wyniki także do pliku F\n";
}

int main(int argc, char** argv) {
    std::vector<std::string> args;
    int threads = std::min(omp_get_num_procs(), MAX_THREADS);
    bool verbose = false;
    std::string out_path;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "-p") {
            if (i + 1 >= argc) {
                std::cerr << "Błąd: -p wymaga liczby wątków (1-" << MAX_THREADS << ").\n";
                return 1;
            }
            char* end = nullptr;
            long v = std::strtol(argv[++i], &end, 10);
            if (*end != '\0' || v < 1) {
                std::cerr << "Błąd: -p wymaga liczby całkowitej od 1 do " << MAX_THREADS << ".\n";
                return 1;
            }
            if (v > MAX_THREADS) {
                std::cerr << "Uwaga: maksymalnie " << MAX_THREADS << " wątków - ustawiam " << MAX_THREADS << ".\n";
                v = MAX_THREADS;
            }
            threads = (int)v;
        } else if (a == "-v") verbose = true;
        else if (a == "-o" && i + 1 < argc) out_path = argv[++i];
        else if (a == "-h" || a == "--help") { usage(argv[0]); return 0; }
        else args.push_back(a);
    }
    if (args.empty()) { usage(argv[0]); return 1; }

    std::vector<std::string> files;
    for (auto& p : args) {
        if (fs::is_directory(p)) {
            std::vector<std::string> v;
            for (auto& e : fs::recursive_directory_iterator(p))
                if (e.is_regular_file()) v.push_back(e.path().string());
            std::sort(v.begin(), v.end());
            files.insert(files.end(), v.begin(), v.end());
        } else if (fs::is_regular_file(p)) {
            files.push_back(p);
        } else {
            std::cerr << "Błąd: nie znaleziono pliku: " << p << "\n";
            return 2;
        }
    }
    if (files.empty()) { std::cerr << "Brak plików.\n"; return 1; }

    for (auto& f : files) g_total_bytes += fs::file_size(f);
    g_total_files = files.size();

    std::vector<std::string> hashes(files.size());
    std::vector<int> owner(files.size(), -1);
    int team_size = 0;

    omp_set_dynamic(0);  // dokładnie tyle wątków, ile podano w -p
    g_start = Clock::now();
    g_last_draw = g_start;

#pragma omp parallel num_threads(threads)
    {
#pragma omp single
        team_size = omp_get_num_threads();

        // Pliki są rozdzielane dynamicznie między wątki; wynik trafia pod indeks pliku.
#pragma omp for schedule(dynamic, 1)
        for (long i = 0; i < (long)files.size(); ++i) {
            hashes[i] = sha256_file(files[i]);
            owner[i] = omp_get_thread_num();
            ++g_done_files;
            draw(false);
        }
    }
    draw(true);

    std::string result;
    for (size_t i = 0; i < files.size(); ++i) result += hashes[i] + "  " + files[i] + "\n";
    std::fputs(result.c_str(), stdout);
    if (!out_path.empty()) std::ofstream(out_path) << result;

    if (verbose)
        for (size_t i = 0; i < files.size(); ++i)
            std::fprintf(stderr, "wątek %2d | %s\n", owner[i], files[i].c_str());

    double el = std::chrono::duration<double>(Clock::now() - g_start).count();
    std::fprintf(stderr, "Gotowe: %zu plików, %.1f MB, wątki OpenMP: %d (zażądano %d), czas: %.3f s\n",
                 files.size(), g_total_bytes / 1e6, team_size, threads, el);
    return 0;
}