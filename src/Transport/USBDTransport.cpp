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

#include <f1x/aasdk/Transport/USBDTransport.hpp>

namespace f1x
{
namespace aasdk
{
namespace transport
{

USBDTransport::USBDTransport(boost::asio::io_service& ioService)
    : receiveStrand_(ioService)
    , sendStrand_(ioService)
{}

void Transport::receive(size_t size, ReceivePromise::Pointer promise)
{
    int ret; 

    receiveStrand_.dispatch([this, self = this->shared_from_this(), size, promise = std::move(promise)]() mutable {
        
        auto usbEndpointPromise = usb::IUSBEndpoint::Promise::defer(receiveStrand_);
        usbEndpointPromise->then([this, self = this->shared_from_this()](auto bytesTransferred) {
            this->receiveHandler(bytesTransferred);
        });

        uint8_t* readMsg;
        ret = read(_fd_usb_out, readMsg, size); // promise?

    });
}

void Transport::send(common::Data data, SendPromise::Pointer promise)
{
    int ret;

    sendStrand_.dispatch([this, self = this->shared_from_this(), data = std::move(data), promise = std::move(promise)]() mutable {

        uint8_t* writeMsg;
        writeMsg = &data[0];
        ret = write(_fd_usb_in, writeMsg, MAX_BUFF_SIZE*sizeof(uint8_t)); // promise?

    });



}

void USBTransport::stop()
{

}

}
}
}
