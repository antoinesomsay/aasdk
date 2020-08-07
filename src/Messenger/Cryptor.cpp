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

#include <algorithm>
#include <functional>
#include <f1x/aasdk/Messenger/Cryptor.hpp>
#include <f1x/aasdk/Error/Error.hpp>

namespace f1x
{
namespace aasdk
{
namespace messenger
{

Cryptor::Cryptor(transport::ISSLWrapper::Pointer sslWrapper, int serv)
    : sslWrapper_(std::move(sslWrapper))
    , maxBufferSize_(1024 * 20)
    , certificate_(nullptr)
    , privateKey_(nullptr)
    , context_(nullptr)
    , ssl_(nullptr)
    , isActive_(false)
    , serv_(serv)
{

}

void Cryptor::init()
{
    std::lock_guard<decltype(mutex_)> lock(mutex_);

    certificate_ = sslWrapper_->readCertificate(cCertificate);

    if(certificate_ == nullptr)
    {
        throw error::Error(error::ErrorCode::SSL_READ_CERTIFICATE);
    }

    privateKey_ = sslWrapper_->readPrivateKey(cPrivateKey);

    if(privateKey_ == nullptr)
    {
        throw error::Error(error::ErrorCode::SSL_READ_PRIVATE_KEY);
    }

    auto method = sslWrapper_->getMethod();

    if(method == nullptr)
    {
        throw error::Error(error::ErrorCode::SSL_METHOD);
    }

    context_ = sslWrapper_->createContext(method);

    if(context_ == nullptr)
    {
        throw error::Error(error::ErrorCode::SSL_CONTEXT_CREATION);
    }

    if(!sslWrapper_->useCertificate(context_, certificate_))
    {
        throw error::Error(error::ErrorCode::SSL_USE_CERTIFICATE);
    }

    if(!sslWrapper_->usePrivateKey(context_, privateKey_))
    {
        throw error::Error(error::ErrorCode::SSL_USE_PRIVATE_KEY);
    }

    ssl_ = sslWrapper_->createInstance(context_);

    if(ssl_ == nullptr)
    {
        throw error::Error(error::ErrorCode::SSL_HANDLER_CREATION);
    }

    bIOs_ = sslWrapper_->createBIOs();

    if(bIOs_.first == nullptr)
    {
        throw error::Error(error::ErrorCode::SSL_READ_BIO_CREATION);
    }

    if(bIOs_.second == nullptr)
    {
        throw error::Error(error::ErrorCode::SSL_WRITE_BIO_CREATION);
    }

    sslWrapper_->setBIOs(ssl_, bIOs_, maxBufferSize_);

    if (serv_)
        sslWrapper_->setAcceptState(ssl_);
    else
        sslWrapper_->setConnectState(ssl_);
}

void Cryptor::deinit()
{
    std::lock_guard<decltype(mutex_)> lock(mutex_);

    if(ssl_ != nullptr)
    {
        sslWrapper_->free(ssl_);
        ssl_ = nullptr;
    }

    bIOs_ = std::make_pair(nullptr, nullptr);

    if(context_ != nullptr)
    {
        sslWrapper_->free(context_);
        context_ = nullptr;
    }

    if(certificate_ != nullptr)
    {
        sslWrapper_->free(certificate_);
        certificate_ = nullptr;
    }

    if(privateKey_ != nullptr)
    {
        sslWrapper_->free(privateKey_);
        privateKey_ = nullptr;
    }
}

bool Cryptor::doHandshake()
{
    std::lock_guard<decltype(mutex_)> lock(mutex_);

    int result;

    if (serv_)
        if (!SSL_is_init_finished(ssl_)) 
            result = sslWrapper_->doHandshake(ssl_);
    else
        result = sslWrapper_->doHandshake(ssl_);
    if(result == SSL_ERROR_WANT_READ)
    {
        return false;
    }
    else if(result == SSL_ERROR_NONE)
    {
        isActive_ = true;
        return true;
    }
    else
    {
        throw error::Error(error::ErrorCode::SSL_HANDSHAKE, result);
    }
}

size_t Cryptor::encrypt(common::Data& output, const common::DataConstBuffer& buffer)
{
    std::lock_guard<decltype(mutex_)> lock(mutex_);

    size_t totalWrittenBytes = 0;

    while(totalWrittenBytes < buffer.size)
    {
        const common::DataConstBuffer currentBuffer(buffer.cdata, buffer.size, totalWrittenBytes);
        const auto writeSize = sslWrapper_->sslWrite(ssl_, currentBuffer.cdata, currentBuffer.size);

        if(writeSize <= 0)
        {
            throw error::Error(error::ErrorCode::SSL_WRITE, sslWrapper_->getError(ssl_, writeSize));
        }

        totalWrittenBytes += writeSize;
    }

    return this->read(output);
}

size_t Cryptor::decrypt(common::Data& output, const common::DataConstBuffer& buffer)
{
    std::lock_guard<decltype(mutex_)> lock(mutex_);

    this->write(buffer);
    const size_t beginOffset = output.size();
    output.resize(beginOffset + 1);

    size_t availableBytes = 1;
    size_t totalReadSize = 0;

    while(availableBytes > 0)
    {
        const auto& currentBuffer = common::DataBuffer(output, totalReadSize + beginOffset);
        auto readSize = sslWrapper_->sslRead(ssl_, currentBuffer.data, currentBuffer.size);

        if(readSize <= 0)
        {
            throw error::Error(error::ErrorCode::SSL_READ, sslWrapper_->getError(ssl_, readSize));
        }

        totalReadSize += readSize;
        availableBytes = sslWrapper_->getAvailableBytes(ssl_);
        output.resize(output.size() + availableBytes);
    }

    return totalReadSize;
}

common::Data Cryptor::readHandshakeBuffer()
{
    std::lock_guard<decltype(mutex_)> lock(mutex_);

    common::Data output;
    this->read(output);
    return output;
}

void Cryptor::writeHandshakeBuffer(const common::DataConstBuffer& buffer)
{
    std::lock_guard<decltype(mutex_)> lock(mutex_);

    this->write(buffer);
}

size_t Cryptor::read(common::Data& output)
{
    const auto pendingSize = sslWrapper_->bioCtrlPending(bIOs_.second);

    size_t beginOffset = output.size();
    output.resize(beginOffset + pendingSize);
    size_t totalReadSize = 0;

    while(totalReadSize < pendingSize)
    {
        const auto& currentBuffer = common::DataBuffer(output, totalReadSize + beginOffset);
        const auto readSize = sslWrapper_->bioRead(bIOs_.second, currentBuffer.data, currentBuffer.size);

        if(readSize <= 0)
        {
            throw error::Error(error::ErrorCode::SSL_BIO_READ, sslWrapper_->getError(ssl_, readSize));
        }

        totalReadSize += readSize;
    }

    return totalReadSize;
}

void Cryptor::write(const common::DataConstBuffer& buffer)
{
    size_t totalWrittenBytes = 0;

    while(totalWrittenBytes < buffer.size)
    {
        const common::DataConstBuffer currentBuffer(buffer.cdata, buffer.size, totalWrittenBytes);
        const auto writeSize = sslWrapper_->bioWrite(bIOs_.first, currentBuffer.cdata, currentBuffer.size);

        if(writeSize <= 0)
        {
            throw error::Error(error::ErrorCode::SSL_BIO_WRITE, sslWrapper_->getError(ssl_, writeSize));
        }

        totalWrittenBytes += writeSize;
    }
}

bool Cryptor::isActive() const
{
    std::lock_guard<decltype(mutex_)> lock(mutex_);

    return isActive_;
}

const std::string Cryptor::cCertificate = "-----BEGIN CERTIFICATE-----\n\
MIIDWzCCAkOgAwIBAgIUNIU/3G/+Xopm9k+dPt2bXc0ZWCUwDQYJKoZIhvcNAQEL\n\
BQAwPTELMAkGA1UEBhMCRlIxCzAJBgNVBAgMAkZSMSEwHwYDVQQKDBhJbnRlcm5l\n\
dCBXaWRnaXRzIFB0eSBMdGQwHhcNMjAwNzI5MDkyNDM0WhcNMjEwNzI5MDkyNDM0\n\
WjA9MQswCQYDVQQGEwJGUjELMAkGA1UECAwCRlIxITAfBgNVBAoMGEludGVybmV0\n\
IFdpZGdpdHMgUHR5IEx0ZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n\
AKmDb9Xt7FzG/P8gFV5OxRj4U5GQjAu4RNVVLhhYr/r6UevCPDp8THiVtZN74QJR\n\
AYv9tUw/7cLNzuQtcBdimrPlqANnMH6+r8HTnrYRsBQVDUMDAR8RIhL6B9G5cuAw\n\
TmiTZ+sywNiPMAtoVpTIr+DT5XH9weU6/61kX9e+YJXcD2a5BvaL4Xc5XOscZEp8\n\
uFNXBVqaKppWuQX1CtPzgqthlEDEf6Od7J7raMJ2G5Yt68iLKGLzAOMCs/FrZ/ew\n\
o4ruDSAfmT5yM16tLrMbw2D25JH6CcL7s6d5/x9fB9KOYLM3/g/NmW0ICUg1uV7l\n\
+p+wR9CQbZX5/EhWqdPJTXcCAwEAAaNTMFEwHQYDVR0OBBYEFN3qFLW/PHj4nLfE\n\
L7sLAuGVr1ldMB8GA1UdIwQYMBaAFN3qFLW/PHj4nLfEL7sLAuGVr1ldMA8GA1Ud\n\
EwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAEN3zl1J/Clpsn99ydLww0Yf\n\
5GC2BryqG0vyi0WASG3JIt7HrxMrBoHgUrHp24s61B3g2jHEE7OUmJtsEgtkVgiJ\n\
vgCTukHoqEg6lEb6ro7xWuRtFBiaUNESMOsR3gHSzjjzgv0YNuaFeUwyL/dE/NGL\n\
w1KsPJht3qvR8tH0eZkw6iz/k7IFFbdr3JiFWPlg9r1guk/R54Gh65a52pDlS5EJ\n\
BrAvWJuLG0bqlqK1ruZNPWscpjc3Z/VW73r+BGXTHfHkczkkkO52olzcDSog5hsA\n\
UV3EfhiryqZdnKCgO3q3QNZLhfH9M7IrvAX1obtmyfpFGv6dVuzgVFlJIY7KLYM=\n\
-----END CERTIFICATE-----\n";




const std::string Cryptor::cPrivateKey = "-----BEGIN PRIVATE KEY-----\n\
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCpg2/V7excxvz/\n\
IBVeTsUY+FORkIwLuETVVS4YWK/6+lHrwjw6fEx4lbWTe+ECUQGL/bVMP+3Czc7k\n\
LXAXYpqz5agDZzB+vq/B0562EbAUFQ1DAwEfESIS+gfRuXLgME5ok2frMsDYjzAL\n\
aFaUyK/g0+Vx/cHlOv+tZF/XvmCV3A9muQb2i+F3OVzrHGRKfLhTVwVamiqaVrkF\n\
9QrT84KrYZRAxH+jneye62jCdhuWLevIiyhi8wDjArPxa2f3sKOK7g0gH5k+cjNe\n\
rS6zG8Ng9uSR+gnC+7Onef8fXwfSjmCzN/4PzZltCAlINble5fqfsEfQkG2V+fxI\n\
VqnTyU13AgMBAAECggEAfmIOmbOADFQYAKcNB3k3HjzXIaphn8NNHrkZWvGUk0za\n\
kyoH+Zr+8NC9xi4QPsfinVsVNrpbLGiBnkH6VpUfvoy1TYQ79eN56ss6g4iAfRiN\n\
AK9WwLDndLqR5d2cNmYNr45nZkY63bs0GO070EYoSznw0aJeU+g/BCnYA2RfYpqu\n\
WWUuOjcC2IqHruLh8hhpjR0Wu4vuAKTlAxI4+SsAsPfFCqy7wB0u7IDVWfJ/wHQv\n\
pIjUKZh0aesb7mOv9Sgqfkl3e1vDhT5pO8fLhBnYfto23J51z0+PUAmv1YMBicVc\n\
9nR1bKjpe8JNlZoIUSFybbs9KGJI7/dHzCOg23M1MQKBgQDekf6wdym76xbIGxok\n\
vyV37QLCi8lpA2YUS6tix4P97kjGzWovc7rnVHtb4TRZr/BuI/YtC0O3090sR3Qt\n\
BhAzu66rqT8c6Mh6BFB+BT1g7lZGW8KqVttewRM1YfGCM1sshk3s/MbT9TSSGSF+\n\
8fwbTDmL3kbe8qYofj3FTFTiJQKBgQDC+Vz3Tb2Dd+zjai0EXfzwdji+yToZTVLs\n\
S8O9uKZVDRu0fQ6amdHHMma8VpB5MdJmbeRqZC6sHvCwDPfw40/8F90dWY/halOx\n\
cNKTrN24ppDJWOyzZe/SzRnodOQsxUuKn7rsspdU9P4jLafsR//DpWr2UEhFmgLM\n\
YlpLUUUoawKBgGiAXfgXCzZbbCfqab0FLp9/XgNgROIUoXI4ETFhAj1RC0SkoA3F\n\
peUFyqHaPI07yYS9R9Hgbxw50qf+qLKXHTZdEecxoRt+xNpdejmhVi9T2JhSbzUx\n\
cPCtcMpowU9js5RVPvNdwDE2+Ub7m7mR/tAGWyKr69S0U4XBuFkRvO0tAoGAS2DO\n\
wUmL4BzoN4+f8dVIacq663+ud4O+cF5mQZ32qGEV+fRzRe/7+1AQCfZJiqFpX3JS\n\
4ZLzvFWF5fpNjRLEpIixUpyClLpfuvUMZE1rtuymg0Fe2YiqbEwhHQ67/FcWenSA\n\
duwgt5az/fOzvRSk3AXC0ZF+L3J4bH4FvKKh4xsCgYAn01WUlGFbSTubT8eD8lZf\n\
nH7yjDgUuJ/gv9yV+6dUX0+kgwgSMhghHw+8N4DBW4QFMhF7ZdJVT5g4RCotnF+7\n\
n4WPGDqdkiGf95I2vInS4MRc931tRGCvELAiPUvBkzbDaYioIb6tJh471yF0T45v\n\
6YQwSZHaH1YXm40Hg61oPw==\n\
-----END PRIVATE KEY-----\n";

}
}
}
