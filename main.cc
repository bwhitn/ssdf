// See the file "COPYING" in the main distribution directory for copyright.

#include "SSDF.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {

using ssdf::SSDF_MINHASH18X24_ALG;
using ssdf::SSDF_MINHASH18X24_VALUES;
using ssdf::SSDF_MINHASH_VALUES;
using ssdf::SSDF_TOKEN_SEPARATOR;
using ssdf::Hasher;

constexpr size_t kDefaultBenchmarkBytes = 16 * 1024 * 1024;

void Usage(const char* argv0) {
    std::cerr << "usage: " << argv0 << " FILE\n"
              << "       " << argv0 << " --compare FILE FILE\n"
              << "       " << argv0 << " --minhash18x24 FILE\n"
              << "       " << argv0 << " --minhash18x24-compare FILE FILE\n"
              << "       " << argv0 << " --chunk-test FILE\n"
              << "       " << argv0 << " --benchmark [FILE ...]\n";
}

bool FeedFile(const std::filesystem::path& path, size_t chunk_size, Hasher& hasher) {
    std::ifstream input(path, std::ios::binary);
    if ( ! input ) {
        std::cerr << "ssdf: cannot open " << path << "\n";
        return false;
    }

    std::vector<uint8_t> buffer(chunk_size);

    while ( input ) {
        input.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
        const auto got = input.gcount();
        if ( got > 0 )
            hasher.update(buffer.data(), static_cast<size_t>(got));
    }

    if ( input.bad() ) {
        std::cerr << "ssdf: error reading " << path << "\n";
        return false;
    }

    return true;
}

std::optional<std::string> HashFile(const std::filesystem::path& path, size_t chunk_size,
                                    Hasher* out_hasher = nullptr) {
    Hasher local_hasher;
    auto& hasher = out_hasher ? *out_hasher : local_hasher;

    if ( ! FeedFile(path, chunk_size, hasher) )
        return std::nullopt;

    return hasher.finalize();
}

int HashCommand(const std::filesystem::path& path) {
    Hasher hasher;
    if ( ! FeedFile(path, 64 * 1024, hasher) )
        return 1;

    auto result = hasher.finalize();
    if ( ! result ) {
        std::cerr << "ssdf: not enough content to produce " << SSDF_MINHASH18X24_ALG << "\n";
        return 2;
    }

    std::cout << SSDF_MINHASH18X24_ALG << ' ' << *result << '\n';
    return 0;
}

int ChunkTestCommand(const std::filesystem::path& path) {
    constexpr std::array<size_t, 5> chunks = {1, 7, 64, 4096, 0};
    std::optional<std::string> expected;
    bool ok = true;

    for ( auto chunk : chunks ) {
        auto actual_chunk = chunk;
        if ( actual_chunk == 0 ) {
            std::error_code ec;
            auto size = std::filesystem::file_size(path, ec);
            actual_chunk = ec || size == 0 ? 1 : static_cast<size_t>(size);
        }

        auto result = HashFile(path, actual_chunk);
        if ( ! result ) {
            std::cerr << "ssdf: chunk " << chunk << " produced no content_sim\n";
            ok = false;
            continue;
        }

        if ( ! expected )
            expected = result;
        else if ( *expected != *result )
            ok = false;

        std::cout << actual_chunk << ' ' << SSDF_MINHASH18X24_ALG << ' ' << *result << '\n';
    }

    return ok ? 0 : 3;
}

std::vector<std::string_view> SplitTokens(std::string_view value) {
    std::vector<std::string_view> tokens;
    size_t start = 0;

    while ( start <= value.size() ) {
        const auto separator = value.find(SSDF_TOKEN_SEPARATOR, start);
        if ( separator == std::string_view::npos ) {
            tokens.emplace_back(value.substr(start));
            break;
        }

        tokens.emplace_back(value.substr(start, separator - start));
        start = separator + 1;
    }

    return tokens;
}

size_t MatchingTokens(std::string_view lhs, std::string_view rhs) {
    const auto lhs_tokens = SplitTokens(lhs);
    const auto rhs_tokens = SplitTokens(rhs);
    const auto n = std::min(lhs_tokens.size(), rhs_tokens.size());
    size_t matches = 0;

    for ( size_t i = 0; i < n; ++i ) {
        if ( lhs_tokens[i] == rhs_tokens[i] )
            ++matches;
    }

    return matches;
}

int CompareCommand(const std::filesystem::path& lhs_path, const std::filesystem::path& rhs_path) {
    Hasher lhs_hasher;
    if ( ! FeedFile(lhs_path, 64 * 1024, lhs_hasher) )
        return 1;

    const auto lhs_sim = lhs_hasher.finalize();
    const auto lhs_minhash = lhs_hasher.minhash_signature();

    Hasher rhs_hasher;
    if ( ! FeedFile(rhs_path, 64 * 1024, rhs_hasher) )
        return 1;

    const auto rhs_sim = rhs_hasher.finalize();
    const auto rhs_minhash = rhs_hasher.minhash_signature();

    if ( ! lhs_sim || ! lhs_minhash ) {
        std::cerr << "ssdf: not enough content to produce " << SSDF_MINHASH18X24_ALG << " for "
                  << lhs_path << "\n";
        return 2;
    }

    if ( ! rhs_sim || ! rhs_minhash ) {
        std::cerr << "ssdf: not enough content to produce " << SSDF_MINHASH18X24_ALG << " for "
                  << rhs_path << "\n";
        return 2;
    }

    size_t matching_80_rows = 0;
    for ( size_t i = 0; i < SSDF_MINHASH_VALUES; ++i ) {
        if ( (*lhs_minhash)[i] == (*rhs_minhash)[i] )
            ++matching_80_rows;
    }

    size_t matching_24_rows = 0;
    for ( size_t i = 0; i < SSDF_MINHASH18X24_VALUES; ++i ) {
        if ( (*lhs_minhash)[i] == (*rhs_minhash)[i] )
            ++matching_24_rows;
    }

    const auto matching_tokens = MatchingTokens(*lhs_sim, *rhs_sim);
    const auto row_80_jaccard = static_cast<double>(matching_80_rows) / SSDF_MINHASH_VALUES;
    const auto row_24_jaccard = static_cast<double>(matching_24_rows) / SSDF_MINHASH18X24_VALUES;
    const auto token_jaccard = static_cast<double>(matching_tokens) / SSDF_MINHASH18X24_VALUES;

    std::cout << "alg=" << SSDF_MINHASH18X24_ALG << '\n'
              << "file_a=" << lhs_path << '\n'
              << "file_b=" << rhs_path << '\n'
              << "raw_minhash_matching_rows=" << matching_80_rows << '/' << SSDF_MINHASH_VALUES << '\n'
              << "raw_minhash_jaccard_estimate=" << std::fixed << std::setprecision(6) << row_80_jaccard << '\n'
              << "content_sim_matching_rows=" << matching_24_rows << '/' << SSDF_MINHASH18X24_VALUES << '\n'
              << "content_sim_row_similarity=" << std::fixed << std::setprecision(6) << row_24_jaccard << '\n'
              << "content_sim_matching_tokens=" << matching_tokens << '/' << SSDF_MINHASH18X24_VALUES << '\n'
              << "content_sim_token_similarity=" << std::fixed << std::setprecision(6) << token_jaccard << '\n'
              << "content_sim_a=" << *lhs_sim << '\n'
              << "content_sim_b=" << *rhs_sim << '\n';

    return 0;
}

uint64_t NextSplitMix(uint64_t& state) {
    state += 0x9e3779b97f4a7c15ULL;
    return ssdf::detail::Mix64(state);
}

void FillRandom(std::vector<uint8_t>& buffer, uint64_t& state) {
    for ( size_t i = 0; i < buffer.size(); i += sizeof(uint64_t) ) {
        auto value = NextSplitMix(state);
        auto n = std::min(sizeof(value), buffer.size() - i);
        std::memcpy(buffer.data() + i, &value, n);
    }
}

void PrintBenchmarkResult(const std::string& name, uint64_t bytes, std::chrono::steady_clock::duration elapsed,
                          const Hasher& hasher, const std::optional<std::string>& sim) {
    const auto seconds = std::chrono::duration<double>(elapsed).count();
    const auto mbps = seconds > 0.0 ? (static_cast<double>(bytes) / (1024.0 * 1024.0)) / seconds : 0.0;
    const auto& stats = hasher.stats();

    std::cout << "name=" << name << " alg=" << SSDF_MINHASH18X24_ALG << " bytes=" << bytes
              << " elapsed_s=" << seconds << " mbps=" << mbps << " rolling_windows=" << stats.rolling_windows
              << " selected_features=" << stats.selected_features << " minhash_updates=" << stats.minhash_updates
              << " content_sim=" << (sim ? *sim : std::string("<none>")) << '\n';
}

void BenchmarkGenerated(const std::string& name, bool random_data, size_t bytes) {
    Hasher hasher;
    std::vector<uint8_t> buffer(64 * 1024);
    uint64_t rng = 0x1234abcd9876ef00ULL;
    uint64_t processed = 0;

    const auto start = std::chrono::steady_clock::now();

    while ( processed < bytes ) {
        const auto n = std::min<uint64_t>(buffer.size(), bytes - processed);
        buffer.resize(static_cast<size_t>(n));

        if ( random_data )
            FillRandom(buffer, rng);
        else
            std::fill(buffer.begin(), buffer.end(), static_cast<uint8_t>('A'));

        hasher.update(buffer.data(), buffer.size());
        processed += buffer.size();
    }

    const auto sim = hasher.finalize();
    const auto end = std::chrono::steady_clock::now();
    PrintBenchmarkResult(name, processed, end - start, hasher, sim);
}

void BenchmarkFile(const std::filesystem::path& path) {
    Hasher hasher;
    const auto start = std::chrono::steady_clock::now();

    if ( ! FeedFile(path, 64 * 1024, hasher) )
        return;

    const auto sim = hasher.finalize();
    const auto end = std::chrono::steady_clock::now();
    PrintBenchmarkResult(path.string(), hasher.stats().bytes_processed, end - start, hasher, sim);
}

int BenchmarkCommand(const std::vector<std::string>& files) {
    BenchmarkGenerated("random", true, kDefaultBenchmarkBytes);
    BenchmarkGenerated("repeated", false, kDefaultBenchmarkBytes);

    for ( const auto& file : files )
        BenchmarkFile(file);

    if ( files.empty() && std::filesystem::exists("/bin/ls") )
        BenchmarkFile("/bin/ls");

    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if ( argc < 2 ) {
        Usage(argv[0]);
        return 1;
    }

    const std::string mode = argv[1];

    if ( mode == "--compare" || mode == "--minhash18x24-compare" || mode == "--minhash18x32-compare" ) {
        if ( argc != 4 ) {
            Usage(argv[0]);
            return 1;
        }

        return CompareCommand(argv[2], argv[3]);
    }

    if ( mode == "--minhash18x24" || mode == "--minhash18x32" ) {
        if ( argc != 3 ) {
            Usage(argv[0]);
            return 1;
        }

        return HashCommand(argv[2]);
    }

    if ( mode == "--chunk-test" ) {
        if ( argc != 3 ) {
            Usage(argv[0]);
            return 1;
        }

        return ChunkTestCommand(argv[2]);
    }

    if ( mode == "--benchmark" ) {
        std::vector<std::string> files;
        for ( int i = 2; i < argc; ++i )
            files.emplace_back(argv[i]);

        return BenchmarkCommand(files);
    }

    if ( ! mode.empty() && mode[0] == '-' ) {
        Usage(argv[0]);
        return 1;
    }

    if ( argc != 2 ) {
        Usage(argv[0]);
        return 1;
    }

    return HashCommand(argv[1]);
}
