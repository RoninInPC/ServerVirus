#pragma once
#include <algorithm>
#include<sstream>
#include <boost/asio/ip/address_v4.hpp>

class IPV4Header final {
public:
    IPV4Header() { std::fill(rep_, rep_ + sizeof(rep_), 0); }

    unsigned char Version() const { return (rep_[0] >> 4) & 0xF; }
    unsigned short HeaderLength() const { return (rep_[0] & 0xF) * 4; }
    unsigned char TypeOfService() const { return rep_[1]; }
    unsigned short TotalLength() const { return Decode(2, 3); }
    unsigned short Identification() const { return Decode(4, 5); }
    bool DontFragment() const { return (rep_[6] & 0x40) != 0; }
    bool MoreFragments() const { return (rep_[6] & 0x20) != 0; }
    unsigned short FragmentOffset() const { return Decode(6, 7) & 0x1FFF; }
    unsigned int TimeToLive() const { return rep_[8]; }
    unsigned char Protocol() const { return rep_[9]; }
    unsigned short HeaderChecksum() const { return Decode(10, 11); }

    boost::asio::ip::address_v4 SourceAddress() const
    {
        boost::asio::ip::address_v4::bytes_type bytes
            = { { rep_[12], rep_[13], rep_[14], rep_[15] } };
        return boost::asio::ip::address_v4(bytes);
    }

    boost::asio::ip::address_v4 DestinationAddress() const
    {
        boost::asio::ip::address_v4::bytes_type bytes
            = { { rep_[16], rep_[17], rep_[18], rep_[19] } };
        return boost::asio::ip::address_v4(bytes);
    }

    friend std::istream& operator>>(std::istream& is, IPV4Header& header)
    {
        is.read(reinterpret_cast<char*>(header.rep_), 20);
        if (header.Version() != 4)
            is.setstate(std::ios::failbit);
        std::streamsize options_length = header.HeaderLength() - 20;
        if (options_length < 0 || options_length > 40)
            is.setstate(std::ios::failbit);
        else
            is.read(reinterpret_cast<char*>(header.rep_) + 20, options_length);
        return is;
    }

private:
    unsigned short Decode(int a, int b) const
    {
        return (rep_[a] << 8) + rep_[b];
    }

    unsigned char rep_[60];
};