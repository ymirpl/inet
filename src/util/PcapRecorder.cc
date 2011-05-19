//
// Copyright (C) 2005 Michael Tuexen
// Copyright (C) 2008 Irene Ruengeler
// Copyright (C) 2009 Thomas Dreibholz
// Copyright (C) 2009 Thomas Reschka
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


#include <errno.h>

#include "PcapRecorder.h"

#include "IPProtocolId_m.h"

#ifdef WITH_UDP
#include "UDPPacket_m.h"
#endif

#ifdef WITH_SCTP
#include "SCTPMessage.h"
#include "SCTPAssociation.h"
#endif

#ifdef WITH_TCP_BASE
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

/* "libpcap" record header. */
struct pcaprec_hdr {
     int32  ts_sec;     /* timestamp seconds */
     uint32 ts_usec;        /* timestamp microseconds */
     uint32 incl_len;   /* number of octets of packet saved in file */
     uint32 orig_len;   /* actual length of packet */
};

typedef struct {
     uint8  dest_addr[6];
     uint8  src_addr[6];
     uint16 l3pid;
} hdr_ethernet_t;


//----

Define_Module(PcapRecorder);

PcapRecorder::~PcapRecorder()
{
}

PcapRecorder::PcapRecorder() : cSimpleModule(), pcapDumper()
{
}

void PcapRecorder::initialize()
{
    const char* file = par("pcapFile");
    snaplen = this->par("snaplen");
    pcapDumper.setVerbosity(par("verbosity").boolValue());
    pcapDumper.setOutStream(ev.getOStream());
    signalList.clear();

    {
        cStringTokenizer signalTokenizer(par("sendingSignalNames"));

        while (signalTokenizer.hasMoreTokens())
            signalList[registerSignal(signalTokenizer.nextToken())] = true;
    }

    {
        cStringTokenizer signalTokenizer(par("receivingSignalNames"));

        while (signalTokenizer.hasMoreTokens())
            signalList[registerSignal(signalTokenizer.nextToken())] = false;
    }

    const char* moduleNames = par("moduleNamePatterns");
    cStringTokenizer moduleTokenizer(moduleNames);

    while (moduleTokenizer.hasMoreTokens())
    {
        bool found = false;
        std::string mname(moduleTokenizer.nextToken());
        bool isAllIndex = (mname.length() > 3) && mname.rfind("[*]") == mname.length() - 3;

        if (isAllIndex)
            mname.replace(mname.length() - 3, 3, "");

        for (cModule::SubmoduleIterator i(getParentModule()); !i.end(); i++)
        {
            cModule *submod = i();
            if (0 == strcmp(isAllIndex ? submod->getName() : submod->getFullName(), mname.c_str()))
            {
                found = true;

                for (SignalList::iterator s = signalList.begin(); s != signalList.end(); s++)
                {
                    if (!submod->isSubscribed(s->first, this))
                    {
                        submod->subscribe(s->first, this);
                        EV << "PcapRecorder " << getFullPath() << " subscribed to "
                           << submod->getFullPath() << ":" << getSignalName(s->first) << endl;
                    }
                }
            }
        }

        if (!found)
        {
            EV << "The module " << mname << (isAllIndex ? "[*]" : "")
                    << " not found for PcapRecorder " << getFullPath() << endl;
        }
    }

    pcapDumper.openPcap(file, snaplen);
}

void PcapRecorder::handleMessage(cMessage *msg)
{
    throw cRuntimeError("This module does not handle messages");
}

void PcapRecorder::receiveSignal(cComponent *source, simsignal_t signalID, cObject *obj)
{
    cPacket *packet = dynamic_cast<cPacket *>(obj);

    if (packet)
    {
        SignalList::const_iterator i = signalList.find(signalID);
        bool l2r = (i != signalList.end()) ? i->second : true;
        recordPacket(packet, l2r);
    }
}

void PcapRecorder::recordPacket(cPacket *msg, bool l2r)
{
    if (!ev.isDisabled())
    {
        EV << "PcapRecorder::recordPacket(" << msg->getFullPath() << ", " << l2r << ")\n";
#ifdef WITH_IPv4
        if (dynamic_cast<IPDatagram *>(msg))
        {
            pcapDumper.dumpIPv4(l2r, "", (IPDatagram *)msg, "");
        }
        else
#endif
#ifdef WITH_SCTP
        if (dynamic_cast<SCTPMessage *>(msg))
        {
            pcapDumper.sctpDump("", (SCTPMessage *)msg, std::string(l2r ? "A" : "B"), std::string(l2r ? "B" : "A"));
        }
        else
#endif
#ifdef WITH_TCP_BASE
        if (dynamic_cast<TCPSegment *>(msg))
        {
            pcapDumper.tcpDump(l2r, "", (TCPSegment *)msg, std::string(l2r ? "A" : "B"), std::string(l2r ? "B" : "A"));
        }
        else
#endif
#ifdef WITH_IPv4
        if (dynamic_cast<ICMPMessage *>(msg))
        {
            ev << "ICMPMessage" << (msg->hasBitError() ? "BitError" : "") << endl;
        }
        else
#endif
        {
            // search for encapsulated IP[v6]Datagram in it
            cPacket *encapmsg = msg;

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
                msg = encapmsg;

#ifdef WITH_IPv4
                if (dynamic_cast<IPDatagram *>(msg))
                    pcapDumper.dumpIPv4(l2r, "", (IPDatagram *)msg);
                else
#endif
#ifdef WITH_IPv6
                if (dynamic_cast<IPv6Datagram *>(msg))
                    pcapDumper.dumpIPv6(l2r, "", (IPv6Datagram *)msg);
                else
#endif
                    ASSERT(0); // cannot get here
            }
        }
    }

#ifdef WITH_IPv4
    if (!pcapDumper.isOpened())
        return;

    bool hasBitError = false;
    IPDatagram *ipPacket = NULL;

    while (msg)
    {
        if (msg->hasBitError())
            hasBitError = true;

        if (NULL != (ipPacket = dynamic_cast<IPDatagram *>(msg)))
            break;

        msg = msg->getEncapsulatedPacket();
    }

    if (ipPacket)
    {
        const simtime_t stime = simulation.getSimTime();
        pcapDumper.writeFrame(stime, ipPacket);
    }
#endif
}

void PcapRecorder::finish()
{
     pcapDumper.dump("", "pcapRecorder finished");
     pcapDumper.closePcap();
}

