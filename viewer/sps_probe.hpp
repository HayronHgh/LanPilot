#pragma once
#include <cstdint>
#include <span>
#include <vector>
#include <stdexcept>
#include <ostream>
#include <sstream>
#include <string>

// Diagnostic-only limited SPS reader. Unsupported syntax fails explicitly;
// never used to accept/modify network data in the viewer or decoder.
namespace rwn::viewer::probe {
class Bits {
    std::span<const std::byte> data_;
    std::size_t position_{};
public:
    explicit Bits(std::span<const std::byte> data) : data_(data) {}
    std::uint32_t read(unsigned n) {
        if (n > 32 || n > data_.size() * 8 - position_) throw std::runtime_error("truncated SPS");
        std::uint32_t value{};
        while (n--) {
            value = (value << 1) | ((std::to_integer<unsigned>(data_[position_/8]) >> (7-position_%8)) & 1);
            ++position_;
        }
        return value;
    }
    std::uint32_t ue() {
        unsigned zeros{};
        while (!read(1)) if (++zeros > 30) throw std::runtime_error("SPS Exp-Golomb overflow");
        return ((1U << zeros)-1U) + read(zeros);
    }
};
inline void print_sps(std::span<const std::byte> annex, std::ostream& out) {
    // Annex-B search; cap SPS RBSP independently from the video payload cap.
    std::size_t begin = annex.size(), end = annex.size();
    for (std::size_t i=0; i+3<annex.size(); ++i) {
        if (annex[i]!=std::byte{0} || annex[i+1]!=std::byte{0} || annex[i+2]!=std::byte{1}) continue;
        if (begin != annex.size()) { end=i; break; }
        if ((std::to_integer<unsigned>(annex[i+3]) & 31U)==7) begin=i+4;
    }
    if (begin>=end || end-begin>4096) throw std::runtime_error("missing/oversized SPS");
    std::vector<std::byte> rbsp;
    unsigned zeros{};
    for (auto i=begin; i<end; ++i) {
        const auto b=std::to_integer<unsigned>(annex[i]);
        if (zeros>=2 && b==3) {
            if (i+1>=end || std::to_integer<unsigned>(annex[i+1])>3) throw std::runtime_error("invalid SPS escape");
            zeros=0; continue;
        }
        rbsp.push_back(annex[i]); zeros=b==0 ? zeros+1 : 0;
    }
    Bits b(rbsp);
    const auto profile=b.read(8), constraints=b.read(8), level=b.read(8);
    b.ue();
    if (profile==100 || profile==110 || profile==122 || profile==244) {
        const auto chroma=b.ue();
        if(chroma>3) throw std::runtime_error("unsupported SPS chroma");
        if(chroma==3) b.read(1);
        b.ue(); b.ue(); b.read(1);
        if(b.read(1)) throw std::runtime_error("diagnostic SPS scaling lists unsupported");
    } else if(profile!=66 && profile!=77 && profile!=88) throw std::runtime_error("unsupported SPS profile");
    b.ue(); const auto poc=b.ue();
    if(poc==0) b.ue();
    else if(poc==1) {
        b.read(1); b.ue(); b.ue(); const auto cycle=b.ue();
        if(cycle>255) throw std::runtime_error("SPS POC cycle limit");
        for(unsigned i=0;i<cycle;++i) b.ue();
    } else if(poc!=2) throw std::runtime_error("invalid SPS POC");
    const auto refs=b.ue(); b.read(1);
    const auto width_minus1=b.ue(), height_minus1=b.ue();
    if(width_minus1>65535 || height_minus1>65535) throw std::runtime_error("SPS dimensions exceed diagnostic bound");
    const auto mbw=width_minus1+1, mbh=height_minus1+1;
    const auto progressive=b.read(1); if(!progressive) b.read(1);
    b.read(1); if(b.read(1)) { b.ue();b.ue();b.ue();b.ue(); }
    out<<"sps profile="<<profile<<" constraints="<<constraints<<" level="<<level
       <<" poc="<<poc<<" refs="<<refs<<" mb_width="<<mbw<<" mb_height="<<mbh;
    if(!b.read(1)) { out<<" vui=0 reorder=unspecified buffering=unspecified\n"; return; }
    if(b.read(1)) { if(b.read(8)==255) { b.read(16);b.read(16); } }
    if(b.read(1)) b.read(1);
    if(b.read(1)) { b.read(3); const auto full=b.read(1); out<<" full_range="<<full;
        if(b.read(1)) { const auto p=b.read(8),t=b.read(8),m=b.read(8); out<<" primaries="<<p<<" transfer="<<t<<" matrix="<<m; } }
    if(b.read(1)) { b.ue();b.ue(); }
    if(b.read(1)) { b.read(32);b.read(32);b.read(1); }
    const auto hrd=[&] { const auto count=b.ue(); if(count>31) throw std::runtime_error("SPS HRD limit");
        b.read(8); for(unsigned i=0;i<=count;++i){ b.ue();b.ue();b.read(1); } b.read(20); };
    const auto nal=b.read(1); if(nal) hrd();
    const auto vcl=b.read(1); if(vcl) hrd();
    if(nal||vcl) b.read(1);
    b.read(1);
    if(!b.read(1)) { out<<" restriction=0 reorder=unspecified buffering=unspecified\n"; return; }
    b.read(1);b.ue();b.ue();b.ue();b.ue();
    const auto reorder=b.ue(), buffering=b.ue();
    out<<" restriction=1 reorder="<<reorder<<" buffering="<<buffering<<'\n';
}
inline void test_sps_reader() {
    std::string bits;
    const auto put=[&](std::uint32_t value,unsigned count) {
        while(count) { --count; bits.push_back(((value>>count)&1U) ? '1':'0'); }
    };
    const auto ue=[&](std::uint32_t value) {
        ++value; unsigned count{}; for(auto n=value;n;n>>=1) ++count;
        bits.append(count-1,'0'); put(value,count);
    };
    put(77,8);put(0,8);put(42,8);ue(0);ue(0);ue(0);ue(0);ue(1);
    put(0,1);ue(119);ue(67);put(1,1);put(1,1);put(0,1);put(0,1);put(1,1);
    while(bits.size()%8) bits.push_back('0');
    std::vector<std::byte> fixture{std::byte{0},std::byte{0},std::byte{1},std::byte{0x67}};
    for(std::size_t i=0;i<bits.size();i+=8) {
        unsigned value{}; for(unsigned j=0;j<8;++j) value=(value<<1)|(bits[i+j]=='1');
        fixture.push_back(static_cast<std::byte>(value));
    }
    std::ostringstream result; print_sps(fixture,result);
    if(result.str()!="sps profile=77 constraints=0 level=42 poc=0 refs=1 mb_width=120 mb_height=68 vui=0 reorder=unspecified buffering=unspecified\n")
        throw std::runtime_error("SPS fixture failed");
    bool rejected{};
    try { std::ostringstream sink; print_sps(std::span(fixture).first(6),sink); }
    catch(const std::runtime_error&) { rejected=true; }
    if(!rejected) throw std::runtime_error("truncated SPS accepted");
    rejected=false;
    try { std::vector<std::byte> zero(8); Bits reader(zero); reader.ue(); }
    catch(const std::runtime_error&) { rejected=true; }
    if(!rejected) throw std::runtime_error("unbounded Exp-Golomb accepted");
}
}
