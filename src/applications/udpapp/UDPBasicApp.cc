//
// Copyright (C) 2000 Institut fuer Telematik, Universitaet Karlsruhe
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


#include <omnetpp.h>
#include "UDPBasicApp.h"
#include "UDPControlInfo_m.h"
#include "IPAddressResolver.h"



Define_Module(UDPBasicApp);

int UDPBasicApp::counter;

void UDPBasicApp::initialize(int stage)
{
    // because of IPAddressResolver, we need to wait until interfaces are registered,
    // address auto-assignment takes place etc.
    if (stage!=3)
        return;

    counter = 0;
    numSent = 0;
    numReceived = 0;
    WATCH(numSent);
    WATCH(numReceived);

    localPort = par("localPort");
    destPort = par("destPort");

    const char *destAddrs = par("destAddresses");
    cStringTokenizer tokenizer(destAddrs);
    const char *token;
    while ((token = tokenizer.nextToken())!=NULL)
        destAddresses.push_back(IPAddressResolver().resolve(token));
    if (destAddresses.empty())
        return;

    /** parse freqArray **/
    const char *holderStr = par("freqArray");
        cStringTokenizer tokenizer2(holderStr);
        const char *token2;
        while ((token2 = tokenizer2.nextToken())!=NULL)
        	freqArrayVals.push_back(token2);

	/** parse changeTimeArray **/

	const char *holderStr2 = par("changeTimeArray");
		cStringTokenizer tokenizer3(holderStr2);
		const char *token3;
		while ((token3 = tokenizer3.nextToken())!=NULL)
            	changeTimeVals.push_back(STR_SIMTIME(token3));
    /** end parse **/


    bindToPort(localPort);

    curFreq = STR_SIMTIME(freqArrayVals[0].c_str()).dbl();

    cMessage *timer = new cMessage("sendTimer");
//    scheduleAt((double)par("messageFreq"), timer);
    scheduleAt(curFreq, timer);

}

IPvXAddress UDPBasicApp::chooseDestAddr()
{
    int k = intrand(destAddresses.size());
    return destAddresses[k];
}

simtime_t UDPBasicApp::getFreqValue() {

	if (simTime() < changeTimeVals[0]) { // first value
		return STR_SIMTIME(freqArrayVals[0].c_str());
	}

	EV << "$$ time is " << simTime() << endl;

	for (unsigned int i=changeTimeVals.size()-1; i >= 0 ; i--) {
		if (simTime() >= changeTimeVals[i]) {
			EV << "$$ time greater than " << changeTimeVals[i] << endl;
/*			if (i+1 < changeTimeVals.size()) {
				EV << "$$ yes i+1 element " << endl;
				if (simTime() < changeTimeVals[i+1]) {
					EV << "$$ i+1 going in " << endl;
					return STR_SIMTIME(freqArrayVals[i+1].c_str());
				}
			}
			else {
				EV << "$$ no i+1 element " << endl;
*/
				return STR_SIMTIME(freqArrayVals[i+1].c_str());
			}
		}
}



cPacket *UDPBasicApp::createPacket()
{
    char msgName[32];
    sprintf(msgName,"UDPBasicAppData-%d", counter++);

    cPacket *payload = new cPacket(msgName);
    payload->setByteLength(par("messageLength").longValue());
    return payload;
}

void UDPBasicApp::sendPacket()
{
    cPacket *payload = createPacket();
    IPvXAddress destAddr = chooseDestAddr();
    sendToUDP(payload, localPort, destAddr, destPort);

    numSent++;
}

void UDPBasicApp::handleMessage(cMessage *msg)
{
    if (msg->isSelfMessage())
    {
        // send, then reschedule next sending
        sendPacket();

//        scheduleAt(simTime()+(double)par("messageFreq"), msg);

    	EV << "## time is: " << simTime() << " freq is: " << getFreqValue() << endl;
        scheduleAt(simTime()+getFreqValue(), msg);
    }
    else
    {
        // process incoming packet
        processPacket(PK(msg));
    }

    if (ev.isGUI())
    {
        char buf[40];
        sprintf(buf, "rcvd: %d pks\nsent: %d pks", numReceived, numSent);
        getDisplayString().setTagArg("t",0,buf);
    }
}


void UDPBasicApp::processPacket(cPacket *msg)
{
    EV << "Received packet: ";
    printPacket(msg);
    delete msg;

    numReceived++;
}

