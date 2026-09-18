#include "rwn/transport/msquic_client.hpp"

#include <filesystem>
#include <iostream>

int main(const int argc, const char* const argv[]) {
    if (argc != 2) {
        std::cerr << "usage: rwn-msquic-probe <absolute-msquic.dll>\n";
        return 2;
    }
    try {
        const auto info = rwn::transport::probe_msquic_runtime(
            std::filesystem::path(argv[1]));
        std::cout << "provider=msquic api=2 version="
                  << info.library_version[0] << '.'
                  << info.library_version[1] << '.'
                  << info.library_version[2] << '.'
                  << info.library_version[3]
                  << " runtime=" << info.loaded_library.string() << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "MsQuic probe failed: " << error.what() << '\n';
        return 1;
    }
}
