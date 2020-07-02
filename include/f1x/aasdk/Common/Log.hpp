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

#include <boost/log/trivial.hpp>

#define AASDK_LOG(severity) BOOST_LOG_TRIVIAL(severity) << "[AaSdk] "

#define TO_UINT(i) static_cast<unsigned int>(static_cast<unsigned char>(i))

#define FILL_HEX(stm, p, s) if (s > 30) for(int id=0;id<30;id++)  \
				stm << " " << TO_UINT(p.data[id]); \
			    else for(int id=0;id<s;id++) \
				stm << " " << TO_UINT(p.data[id])


#define FILL_CHEX(stm, p, s) if (s > 30) for(int id=0;id<30;id++)  \
				stm << " " << TO_UINT(p.cdata[id]);\
			    else for(int id=0;id<s;id++)\
				stm << " " << TO_UINT(p.cdata[id])

