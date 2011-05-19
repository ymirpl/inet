//
// Copyright (C) 2005 Michael Tuexen
//                    2008 Irene Ruengeler
//                    2009 Thomas Dreibholz
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

#ifndef __TCPDUMP_H
#define __TCPDUMP_H


#include "INETDefs.h"

#include "PcapDump.h"

// Foreign declarations:
class IPDatagram;
class IPv6Datagram;
class SCTPMessage;
class TCPSegment;

#define RBUFFER_SIZE 65535

/* "libpcap" file header (minus magic number). */
struct pcap_hdr {
     uint32 magic;      /* magic */
     uint16 version_major;   /* major version number */
     uint16 version_minor;   /* minor version number */
     uint32 thiszone;   /* GMT to local correction */
     uint32 sigfigs;        /* accuracy of timestamps */
     uint32 snaplen;        /* max length of captured packets, in octets */
     uint32 network;        /* data link type */
};

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

/* T.D. 22.09.09: commented this out, since it is not used anywhere.
static hdr_ethernet_t HDR_ETHERNET = {
     {0x02, 0x02, 0x02, 0x02, 0x02, 0x02},
     {0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
     0};
*/

/**
 * Dumps every packet using the PcapDump class
 */
class INET_API TCPDump : public cSimpleModule
{
    protected:
        unsigned char* ringBuffer[RBUFFER_SIZE];
        PcapDump tcpdump;
        unsigned int snaplen;
        unsigned long first, last, space;
        bool showBadFrames;
        bool dumpBadFrames;
        bool dropBadFrames;

    public:
        TCPDump();
        ~TCPDump();
        virtual void handleMessage(cMessage *msg);
        virtual void initialize();
        virtual void finish();
};

#endif

