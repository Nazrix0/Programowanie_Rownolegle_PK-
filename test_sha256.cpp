#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>
#include "sha256.hpp"

static int failed = 0, passed = 0;

static void check(const std::string& name, const std::string& got, const std::string& want) {
    if (got == want) { ++passed; }
    else { ++failed; std::printf("BLAD: %s\n  jest:     %s\n  oczekiwano: %s\n", name.c_str(), got.c_str(), want.c_str()); }
}

int main() {
    // Wektory testowe NIST / FIPS 180-4
    check("pusty ciag", Sha256::hash_string(""),
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    check("abc", Sha256::hash_string("abc"),
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    check("448 bitow", Sha256::hash_string("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    // Milion znakow 'a' podawany w kawalkach (test update w partiach)
    {
        Sha256 s;
        std::string chunk(1000, 'a');
        for (int i = 0; i < 1000; ++i) s.update((const uint8_t*)chunk.data(), chunk.size());
        check("milion 'a'", Sha256::to_hex(s.finish()),
              "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    }

    // Granice paddingu - wartosci wzorcowe z Pythona (hashlib)
    struct Case { size_t n; const char* want; };
    const Case cases[] = {
    {1, "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"},
    {55, "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"},
    {56, "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"},
    {57, "f13b2d724659eb3bf47f2dd6af1accc87b81f09f59f2b75e5c0bed6589dfe8c6"},
    {63, "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34"},
    {64, "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"},
    {65, "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0"},
    {119, "31eba51c313a5c08226adf18d4a359cfdfd8d2e816b13f4af952f7ea6584dcfb"},
    {120, "2f3d335432c70b580af0e8e1b3674a7c020d683aa5f73aaaedfdc55af904c21c"},
    {128, "6836cf13bac400e9105071cd6af47084dfacad4e5e302c94bfed24e013afb73e"},
    {1000, "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"}
    };
    for (const auto& c : cases)
        check("'a' x " + std::to_string(c.n), Sha256::hash_string(std::string(c.n, 'a')), c.want);

    // Ten sam wynik niezaleznie od sposobu dzielenia danych
    {
        std::string data(5000, 'x');
        for (size_t i = 0; i < data.size(); ++i) data[i] = (char)(i * 31 + 7);
        std::string whole = Sha256::hash_string(data);
        for (size_t step : {1, 3, 63, 64, 65, 1000}) {
            Sha256 s;
            for (size_t i = 0; i < data.size(); i += step)
                s.update((const uint8_t*)data.data() + i, std::min(step, data.size() - i));
            check("porcje po " + std::to_string(step), Sha256::to_hex(s.finish()), whole);
        }
    }

    std::printf("Testy: %d OK, %d bledow\n", passed, failed);
    return failed ? 1 : 0;
}