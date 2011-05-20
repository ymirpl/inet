//
// Copyright (C) 2005 Michael Tuexen
// Copyright (C) 2008 Irene Ruengeler
// Copyright (C) 2009 Thomas Dreibholz
// Copyright (C) 2011 Zoltan Bojthe
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//

#ifndef __INET_PCAPDUMP_H
#define __INET_PCAPDUMP_H


#include "INETDefs.h"

// Foreign declarations:
class IPDatagram;


/**
 * Dumps packets in PCAP format.
 */
class PcapDump
{
    protected:
        FILE *dumpfile;         // pcap file
        unsigned int snaplen;   // max. length of packets in pcap file
    public:
        PcapDump();

        ~PcapDump();

        void openPcap(const char* filename, unsigned int snaplen);

        bool isOpened() { return (dumpfile != NULL); }

        void closePcap();

        void writeFrame(simtime_t time, const IPDatagram *ipPacket);
};


#endif // __INET_PCAPDUMP_H

