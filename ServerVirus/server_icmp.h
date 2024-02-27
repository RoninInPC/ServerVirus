#pragma once
#include <boost/asio.hpp>
#include <istream>
#include <iostream>
#include <ostream>

#include"icmp_header.h"
#include"ipv4_header.h"
using boost::asio::ip::icmp;
using boost::asio::steady_timer;
namespace chrono = boost::asio::chrono;

class ServerICMP final {

private:
    icmp::resolver resolver_;
    std::vector<icmp::endpoint> destinations_;
    icmp::socket socket_;
    steady_timer timer_;
    unsigned short sequence_number_;
    chrono::steady_clock::time_point time_sent_;
    boost::asio::streambuf reply_buffer_;
    std::size_t num_replies_;

public:
    ServerICMP(boost::asio::io_context& io_context)
        : resolver_(io_context), socket_(io_context, icmp::v4()),
        timer_(io_context), sequence_number_(0), num_replies_(0)
    {
        
    }

private:
    void StartSend(const std::string& message)
    {
        std::string body(message);


        ICMPHeader echo_request;
        echo_request.Type(ICMPHeader::echo_request);
        echo_request.Code(0);
        echo_request.Identifier(GetIdentifier());
        echo_request.SequenceNumber(++sequence_number_);
        ComputeChecksum(echo_request, body.begin(), body.end());


        boost::asio::streambuf request_buffer;
        std::ostream os(&request_buffer);
        os << echo_request << body;


        time_sent_ = steady_timer::clock_type::now();
        socket_.send_to(request_buffer.data());


        num_replies_ = 0;
        timer_.expires_at(time_sent_ + chrono::seconds(5));
        timer_.async_wait(std::bind(&ServerICMP::Timeout, this));
    }

    void Timeout()
    {
        if (num_replies_ == 0)
            std::cout << "Request timed out" << std::endl;


        timer_.expires_at(time_sent_ + chrono::seconds(1));
        timer_.async_wait(std::bind(&Sender::StartSend, this));
    }

    void StartReceive() {

        reply_buffer_.consume(reply_buffer_.size());


        socket_.async_receive(reply_buffer_.prepare(65536),
            std::bind(&ServerICMP::HandleReceive, this, std::placeholders::_2));
    }

    void HandleReceive(std::size_t length)
    {

        reply_buffer_.commit(length);


        std::istream is(&reply_buffer_);
        IPV4Header ipv4_hdr;
        ICMPHeader icmp_hdr;
        is >> ipv4_hdr >> icmp_hdr;


        if (is && icmp_hdr.Type() == ICMPHeader::echo_reply
            && icmp_hdr.Identifier() == GetIdentifier()
            && icmp_hdr.SequenceNumber() == sequence_number_)
        {
            if (num_replies_++ == 0)
                timer_.cancel();

            chrono::steady_clock::time_point now = chrono::steady_clock::now();
            chrono::steady_clock::duration elapsed = now - time_sent_;
            std::cout << length - ipv4_hdr.HeaderLength()
                << " bytes from " << ipv4_hdr.SourceAddress()
                << ": icmp_seq=" << icmp_hdr.SequenceNumber()
                << ", ttl=" << ipv4_hdr.TimeToLive()
                << ", time="
                << chrono::duration_cast<chrono::milliseconds>(elapsed).count()
                << std::endl;
        }

        StartReceive();
    }

    static unsigned short GetIdentifier()
    {
#if defined(BOOST_ASIO_WINDOWS)
        return static_cast<unsigned short>(::GetCurrentProcessId());
#else
        return static_cast<unsigned short>(::getpid());
#endif
    }


};