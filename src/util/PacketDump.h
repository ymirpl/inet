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

#ifndef __INET_PACKETDUMP_H
#define __INET_PACKETDUMP_H


#include "INETDefs.h"

// Foreign declarations:
class IPDatagram;
class IPv6Datagram;
class SCTPMessage;
class TCPSegment;
class UDPPacket;


/**
 * Dumps packet infos to output stream.
 */
class PacketDump
{
    protected:
        bool verbose;
        std::ostream *outp;
    public:
        PacketDump();

        ~PacketDump();

        void setOutStream(std::ostream& o) { outp = &o; }

        void setVerbose(bool verb) { verbose = verb; }

        // dumps arbitary text
        void dump(const char *label, const char *msg);

        void dumpPacket(bool l2r, cPacket *packet);

        void dumpIPv4(bool l2r, const char *label, IPDatagram *dgram, const char *comment = NULL);

        void dumpIPv6(bool l2r, const char *label, IPv6Datagram *dgram, const char *comment = NULL);

        void sctpDump(const char *label, SCTPMessage *sctpmsg, const std::string& srcAddr,
                const std::string& destAddr, const char *comment=NULL);

        void tcpDump(bool l2r, const char *label, TCPSegment *tcpseg, const std::string& srcAddr,
                const std::string& destAddr, const char *comment=NULL);

        void udpDump(bool l2r, const char *label, UDPPacket* udppkt, const std::string& srcAddr,
                const std::string& destAddr, const char *comment);
};

#endif // __INET_PACKETDUMP_H

