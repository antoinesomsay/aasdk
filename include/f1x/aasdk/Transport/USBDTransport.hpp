/*
*  This file is part of aasdk library project.
*  Copyright (C) 2018 f1x.studio (Michal Szwaj)
*
*  aasdk is free software: you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 3 of the License, or
*  (at your option) any later version.

*  aasdk is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with aasdk. If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <list>
#include <queue>
#include <boost/asio.hpp>
#include <f1x/aasdk/Transport/ITransport.hpp>
#include <f1x/aasdk/Transport/DataSink.hpp>
#define MAX_BUFF_SIZE 1024
extern "C" {
#include <unistd.h>
};



namespace f1x
{
namespace aasdk
{
namespace transport
{

class USBDTransport: public ITransport, public std::enable_shared_from_this<Transport>, boost::noncopyable
{
public:
    USBDTransport(boost::asio::io_service& ioService);

    void receive(size_t size, ReceivePromise::Pointer promise) override;
    void send(common::Data data, SendPromise::Pointer promise) override;

private:
    boost::asio::io_service::strand receiveStrand_;
    boost::asio::io_service::strand sendStrand_;
    int _fd_usb_out;
    int _fd_usb_in;
};

}
}
}
