//
// Copyright (C) 2005 Michael Tuexen
//               2008 Irene Ruengeler
//               2009 Thomas Dreibholz
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
package inet.util;

//
// Provides tcpdump-like functionality: dumps packet contents on the
// module output, and optionally records them into a PCAP file.
// This module has to be placed into the packet's path, and connected
// both sides.
//
// This module is deprecated: consider using PcapRecorder, which
// can be inserted into compound modules non-intrusively (it receives
// packet data via signals, so existing modules don't need to be reconnected.)
//
simple TCPDump {
    parameters:
        string dumpFile = default("");
        int snaplen = default(65535);
        bool verbose = default(false);
        bool dumpBadFrames = default(true); // write bad frames to pcap file
        bool dropBadFrames = default(false);
    gates:
        input ifIn[];
        input in2[];
        output ifOut[];
        output out2[];
}
