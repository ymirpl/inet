//
// Copyright (C) 2005 Michael Tuexen
// Copyright (C) 2008 Irene Ruengeler
// Copyright (C) 2009 Thomas Dreibholz
// Copyright (C) 2009 Thomas Reschka
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


#include <errno.h>

#include "TCPDump.h"

#include "IPProtocolId_m.h"

#ifdef WITH_UDP
#include "UDPPacket_m.h"
#endif

#ifdef WITH_SCTP
#include "SCTPMessage.h"
#include "SCTPAssociation.h"
#endif

#ifdef WITH_TCP_COMMON
#include "TCPSegment.h"
#endif

#ifdef WITH_IPv4
#include "ICMPMessage.h"
#include "IPAddress.h"
#include "IPControlInfo_m.h"
#include "IPDatagram.h"
#include "IPSerializer.h"
#endif

#ifdef WITH_IPv6
#include "IPv6Datagram.h"
#endif

#if !defined(_WIN32) && !defined(__CYGWIN__) && !defined(_WIN64)
#include <netinet/in.h>  // htonl, ntohl, ...
#endif

#define MAXBUFLENGTH 65536

//----

Define_Module(TCPDump);

TCPDump::TCPDump() : cSimpleModule(), tcpdump()
{
}

TCPDump::~TCPDump()
{
}

void TCPDump::initialize()
{
    const char* file = this->par("dumpFile");

    showBadFrames = par("showBadFrames").boolValue();
    dumpBadFrames = par("dumpBadFrames").boolValue();
    dropBadFrames = par("dropBadFrames").boolValue();

    snaplen = this->par("snaplen");
    tcpdump.setVerbosity(par("verbosity").boolValue());
    tcpdump.setOutStream(ev.getOStream());

    tcpdump.openPcap(file, snaplen);
}

void TCPDump::handleMessage(cMessage *msg)
{
    if (!ev.isDisabled() && (showBadFrames || !PK(msg)->hasBitError()))
    {
        bool l2r = msg->arrivedOn("in1");

#ifdef WITH_IPv4
        if (dynamic_cast<IPDatagram *>(msg))
        {
            tcpdump.dumpIPv4(l2r, "", (IPDatagram *)msg, "");
        }
        else
#endif
#ifdef WITH_SCTP
        if (dynamic_cast<SCTPMessage *>(msg))
        {
            tcpdump.sctpDump("", (SCTPMessage *)msg, std::string(l2r ? "A" : "B"), std::string(l2r ? "B" : "A"));
        }
        else
#endif
#ifdef TCP_COMMON
        if (dynamic_cast<TCPSegment *>(msg))
        {
            tcpdump.tcpDump(l2r, "", (TCPSegment *)msg, std::string(l2r ? "A" : "B"), std::string(l2r ? "B" : "A"));
        }
        else
#endif
#ifdef WITH_IPv4
        if (dynamic_cast<ICMPMessage *>(msg))
        {
            ev << "ICMPMessage" << (((ICMPMessage *)msg)->hasBitError() ? "BitError" : "") << endl;
        }
        else
#endif
        {
            // search for encapsulated IP[v6]Datagram in it
            cPacket *encapmsg = PK(msg);

            while (encapmsg
#ifdef WITH_IPv4
                    && dynamic_cast<IPDatagram *>(encapmsg) == NULL
#endif
#ifdef WITH_IPv6
                    && dynamic_cast<IPv6Datagram_Base *>(encapmsg) == NULL
#endif
                )
            {
                encapmsg = encapmsg->getEncapsulatedPacket();
            }

            if (!encapmsg)
            {
                //We do not want this to end in an error if EtherAutoconf messages
                //are passed, so just print a warning. -WEI
                EV << "CANNOT DECODE: packet " << msg->getName() << " doesn't contain either IP or IPv6 Datagram\n";
            }
            else
            {
#ifdef WITH_IPv4
                if (dynamic_cast<IPDatagram *>(encapmsg))
                    tcpdump.dumpIPv4(l2r, "", (IPDatagram *)encapmsg);
                else
#endif
#ifdef WITH_IPv6
                if (dynamic_cast<IPv6Datagram *>(encapmsg))
                    tcpdump.dumpIPv6(l2r, "", (IPv6Datagram *)encapmsg);
                else
#endif
                    ASSERT(0); // cannot get here
            }
        }
    }

#ifdef WITH_IPv4
    if (tcpdump.isOpened() && dynamic_cast<IPDatagram *>(msg) && (dumpBadFrames || !PK(msg)->hasBitError()))
    {
        const simtime_t stime = simulation.getSimTime();
        IPDatagram *ipPacket = check_and_cast<IPDatagram *>(msg);
        tcpdump.writeFrame(stime, ipPacket);
    }
#endif

    if (PK(msg)->hasBitError() && dropBadFrames)
    {
        delete msg;
        return;
    }

    // forward
    int32 index = msg->getArrivalGate()->getIndex();
    int32 id;

    if (msg->getArrivalGate()->isName("ifIn"))
        id = findGate("out2",index);
    else
        id = findGate("ifOut",index);

    send(msg, id);
}

void TCPDump::finish()
{
    tcpdump.dump("", "tcpdump finished");
    tcpdump.closePcap();
}

