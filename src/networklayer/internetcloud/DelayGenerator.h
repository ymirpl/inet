//
// Copyright (C) 2010 Philipp Berndt
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//

#ifndef __INET_INTERNETCLOUD_DELAYGENERATOR_H
#define __INET_INTERNETCLOUD_DELAYGENERATOR_H

#ifndef HAVE_GNPLIB
#error Please install gnplib or disable 'Internet Cloud' feature
#endif

#include "INETDefs.h"

class INET_API DelayGenerator : public cSimpleModule
{
  public:
    inline virtual int numInitStages() const  {return 2;}
    virtual void initialize(int stage);

    void handleMessage(cMessage *msg);

  private:
    int outGateId;
};

#endif  // __INET_INTERNETCLOUD_DELAYGENERATOR_H

