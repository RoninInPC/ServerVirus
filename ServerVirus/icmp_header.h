#pragma once
#include <istream>
#include <ostream>
#include <algorithm>


class ICMPHeader final {
public:
    enum {
        echo_reply = 0, destination_unreachable = 3, source_quench = 4,
        redirect = 5, echo_request = 8, time_exceeded = 11, parameter_problem = 12,
        timestamp_request = 13, timestamp_reply = 14, info_request = 15,
        info_reply = 16, address_request = 17, address_reply = 18
    };

    ICMPHeader() { std::fill(rep_, rep_ + sizeof(rep_), 0); }

    unsigned char Type() const { return rep_[0]; }
    unsigned char Code() const { return rep_[1]; }
    unsigned short Checksum() const { return Decode(2, 3); }
    unsigned short Identifier() const { return Decode(4, 5); }
    unsigned short SequenceNumber() const { return Decode(6, 7); }

    void Type(unsigned char n) { rep_[0] = n; }
    void Code(unsigned char n) { rep_[1] = n; }
    void Checksum(unsigned short n) { Encode(2, 3, n); }
    void Identifier(unsigned short n) { Encode(4, 5, n); }
    void SequenceNumber(unsigned short n) { Encode(6, 7, n); }

    friend std::istream& operator>>(std::istream& is, ICMPHeader& header)
    {
        return is.read(reinterpret_cast<char*>(header.rep_), 8);
    }

    friend std::ostream& operator<<(std::ostream& os, const ICMPHeader& header)
    {
        return os.write(reinterpret_cast<const char*>(header.rep_), 8);
    }

private:
    unsigned short Decode(int a, int b) const
    {
        return (rep_[a] << 8) + rep_[b];
    }

    void Encode(int a, int b, unsigned short n)
    {
        rep_[a] = static_cast<unsigned char>(n >> 8);
        rep_[b] = static_cast<unsigned char>(n & 0xFF);
    }

    unsigned char rep_[8];
};

template <typename Iterator>
void ComputeChecksum(ICMPHeader& header,
    Iterator body_begin, Iterator body_end)
{
    unsigned int sum = (header.Type() << 8) + header.Code()
        + header.Identifier() + header.SequenceNumber();

    Iterator body_iter = body_begin;
    while (body_iter != body_end)
    {
        sum += (static_cast<unsigned char>(*body_iter++) << 8);
        if (body_iter != body_end)
            sum += static_cast<unsigned char>(*body_iter++);
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    header.Checksum(static_cast<unsigned short>(~sum));
}