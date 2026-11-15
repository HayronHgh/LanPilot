#include "rwn/platform/enrollment_tcp.hpp"
#include <algorithm>
#include <charconv>
#include <cstring>
#include <limits>
#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#else
#include <Security/SecRandom.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#endif
namespace rwn::platform::enrollment {
namespace {
namespace e=core::enrollment;
using Clock=core::PairingConsent::Clock;
void require(bool b){if(!b)throw std::runtime_error("pairing connection unavailable or timed out");}
#if defined(_WIN32)
using Socket=SOCKET;constexpr auto invalid=INVALID_SOCKET;
void close_socket(Socket s){closesocket(s);}
bool pending(){const auto x=WSAGetLastError();return x==WSAEWOULDBLOCK || x==WSAEINPROGRESS || x==WSAEINTR;}
struct Winsock{Winsock(){WSADATA data{};require(WSAStartup(MAKEWORD(2,2),&data)==0);}~Winsock(){WSACleanup();}};
void initialize(){static Winsock runtime;}
void nonblocking(Socket s){u_long enabled=1;require(ioctlsocket(s,FIONBIO,&enabled)==0);SetHandleInformation(reinterpret_cast<HANDLE>(s),HANDLE_FLAG_INHERIT,0);}
#else
using Socket=int;constexpr auto invalid=-1;
void close_socket(Socket s){::close(s);}
bool pending(){return errno==EAGAIN || errno==EWOULDBLOCK || errno==EINPROGRESS || errno==EINTR;}
void initialize(){}
void nonblocking(Socket s){require(fcntl(s,F_SETFL,O_NONBLOCK)==0 && fcntl(s,F_SETFD,FD_CLOEXEC)==0);int yes=1;require(setsockopt(s,SOL_SOCKET,SO_NOSIGPIPE,&yes,sizeof(yes))==0);}
#endif
struct Owned {
    Socket value{invalid};explicit Owned(Socket s=invalid):value(s){}~Owned(){if(value!=invalid)close_socket(value);}
    Socket release(){auto s=value;value=invalid;return s;}Owned(const Owned&)=delete;
};
bool wait(Socket s,bool writing,std::chrono::milliseconds timeout){
    require(timeout>=std::chrono::milliseconds::zero() && timeout<=std::chrono::seconds{120});
#if !defined(_WIN32)
    require(s>=0 && s<FD_SETSIZE);
#endif
    fd_set set;FD_ZERO(&set);FD_SET(s,&set);timeval t{};t.tv_sec=static_cast<long>(timeout.count()/1000);t.tv_usec=static_cast<long>((timeout.count()%1000)*1000);
    const auto n=select(
#if defined(_WIN32)
        0,
#else
        s+1,
#endif
        writing?nullptr:&set,writing?&set:nullptr,nullptr,&t);
    if(n<0 && pending())return false;
    require(n>=0);return n>0;
}
sockaddr_in address(std::array<std::byte,4> ip,std::uint16_t port){
    std::string text;for(auto b:ip){if(!text.empty())text+='.';text+=std::to_string(std::to_integer<unsigned>(b));}(void)parse_private_ipv4(text);
    sockaddr_in a{};a.sin_family=AF_INET;a.sin_port=htons(port);std::memcpy(&a.sin_addr,ip.data(),4);return a;
}
class Channel final:public e::EnrollmentChannel {
public:
    explicit Channel(Socket s):socket_(s){}
    Read read(std::span<std::byte> bytes,std::chrono::milliseconds timeout)override{
        require(socket_.value!=invalid && !bytes.empty() && bytes.size()<=131104);
        if(!wait(socket_.value,false,timeout))return {};
        const auto n=recv(socket_.value,reinterpret_cast<char*>(bytes.data()),static_cast<int>(std::min<std::size_t>(bytes.size(),65536)),0);
        if(n<0 && pending())return {};
        require(n>=0);return {static_cast<std::size_t>(n),n==0};
    }
    void write(std::span<const std::byte> b,Clock::time_point deadline,const std::atomic_bool& cancelled)override{
        require(!b.empty() && b.size()<=131104);std::size_t offset{};
        while(offset<b.size()){
            require(!cancelled && Clock::now()<deadline && socket_.value!=invalid);if(!wait(socket_.value,true,std::chrono::milliseconds{20}))continue;
            const auto n=send(socket_.value,reinterpret_cast<const char*>(b.data()+offset),static_cast<int>(std::min<std::size_t>(b.size()-offset,65536)),0);
            if(n<0 && pending())continue;
            require(n>0);offset+=static_cast<std::size_t>(n);
        }
    }
    void close()noexcept override{if(socket_.value!=invalid){close_socket(socket_.value);socket_.value=invalid;}}
private:Owned socket_;
};
class Acceptor final:public Listener {
public:
    Acceptor(std::array<std::byte,4> ip,std::uint16_t port):socket_(::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP)){
        require(socket_.value!=invalid);nonblocking(socket_.value);const auto a=address(ip,port);
        int yes=1;
#if defined(_WIN32)
        require(setsockopt(socket_.value,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,reinterpret_cast<const char*>(&yes),sizeof(yes))==0);
#else
        require(setsockopt(socket_.value,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes))==0);
#endif
        require(::bind(socket_.value,reinterpret_cast<const sockaddr*>(&a),sizeof(a))==0 && ::listen(socket_.value,1)==0);
        sockaddr_in actual{};
#if defined(_WIN32)
        int length=sizeof(actual);
#else
        socklen_t length=sizeof(actual);
#endif
        require(getsockname(socket_.value,reinterpret_cast<sockaddr*>(&actual),&length)==0);port_=ntohs(actual.sin_port);
    }
    std::unique_ptr<e::EnrollmentChannel> accept(std::chrono::milliseconds timeout)override{
        if(!wait(socket_.value,false,timeout))return {};
        Owned client(::accept(socket_.value,nullptr,nullptr));
        if(client.value==invalid && pending())return {};
        require(client.value!=invalid);nonblocking(client.value);return std::make_unique<Channel>(client.release());
    }
    std::uint16_t port()const override{return port_;}
private:Owned socket_;std::uint16_t port_{};
};
}
std::array<std::byte,4> parse_private_ipv4(std::string_view s){
    std::array<std::byte,4> result{};std::size_t start{};
    for(std::size_t i=0;i<4;++i){const auto end=s.find('.',start);require((i==3)==(end==std::string_view::npos));
        const auto part=s.substr(start,end==std::string_view::npos?end:end-start);unsigned n{};const auto parsed=std::from_chars(part.data(),part.data()+part.size(),n);
        require(!part.empty() && (part.size()==1 || part.front()!='0') && parsed.ec==std::errc{} && parsed.ptr==part.data()+part.size() && n<=255);result[i]=static_cast<std::byte>(n);start=end+1;
    }
    const auto a=std::to_integer<unsigned>(result[0]),b=std::to_integer<unsigned>(result[1]);require(a==10 || a==127 || (a==172 && b>=16 && b<=31) || (a==192 && b==168));return result;
}
void secure_random(std::span<std::byte> bytes){require(!bytes.empty() && bytes.size()<=4096);
#if defined(_WIN32)
    require(BCryptGenRandom(nullptr,reinterpret_cast<PUCHAR>(bytes.data()),static_cast<ULONG>(bytes.size()),BCRYPT_USE_SYSTEM_PREFERRED_RNG)>=0);
#else
    require(SecRandomCopyBytes(kSecRandomDefault,bytes.size(),reinterpret_cast<std::uint8_t*>(bytes.data()))==errSecSuccess);
#endif
}
std::unique_ptr<Listener> listen(std::array<std::byte,4> ip,std::uint16_t port){initialize();return std::make_unique<Acceptor>(ip,port);}
std::unique_ptr<e::EnrollmentChannel> connect(std::array<std::byte,4> ip,std::uint16_t port,std::chrono::milliseconds timeout,const std::atomic_bool& cancelled){
    initialize();require(!cancelled && port>0 && timeout>std::chrono::milliseconds::zero() && timeout<=std::chrono::seconds{120});Owned s(::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP));require(s.value!=invalid);nonblocking(s.value);
    const auto a=address(ip,port);const auto started=::connect(s.value,reinterpret_cast<const sockaddr*>(&a),sizeof(a));if(started!=0)require(pending());
    const auto deadline=Clock::now()+timeout;while(started!=0){require(!cancelled && Clock::now()<deadline);if(!wait(s.value,true,std::chrono::milliseconds{20}))continue;int error{};
#if defined(_WIN32)
        int size=sizeof(error);
#else
        socklen_t size=sizeof(error);
#endif
        require(getsockopt(s.value,SOL_SOCKET,SO_ERROR,reinterpret_cast<char*>(&error),&size)==0 && error==0);break;
    }return std::make_unique<Channel>(s.release());
}
}
