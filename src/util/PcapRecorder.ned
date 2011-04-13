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
package inet.util;

//
// Provides tcpdump-like functionality
//
simple PcapRecorder {
    parameters:
        int verbosity = default(0);

        string dumpFile = default("");
        int snaplen = default(65535);

        string moduleNamePattern = default("wlan[*] eth[*] ppp[*]");
              // Space separated list of modulenames (which child of parent module of PcapRecorder)
              // (The program compares elements with getFullName() when element not terminated with '[*]'
              // or cut '[*]' and compare with getName() when name terminated with '[*]'.)
        string sendingSignalNames = default("packetSentToLower"); // List of outbound signals
        string receivingSignalNames = default("packetReceivedFromLower"); // List of incoming signals
        string packetPattern = default(""); // not implemented yet.
}
