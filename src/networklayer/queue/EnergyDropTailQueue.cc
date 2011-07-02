//
// Copyright (C) 2005 Andras Varga
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
#include "EnergyDropTailQueue.h"


Define_Module(EnergyDropTailQueue);

void EnergyDropTailQueue::initialize()
{
    PassiveQueueBase::initialize();
    queue.setName("l2queue");

    qlenVec.setName("queue length");
    dropVec.setName("drops");

    outGate = gate("out");
    energy = 0;

    // configuration
    frameCapacity = par("frameCapacity");
}

bool EnergyDropTailQueue::enqueue(cMessage *msg)
{
    if (frameCapacity && queue.length() >= frameCapacity)
    {
        EV << "Queue full, dropping packet.\n";
        delete msg;
        dropVec.record(1);
        return true;
    }
    else
    {
        queue.insert(msg);
        qlenVec.record(queue.length());
        energy++;
        return false;
    }
}

cMessage *EnergyDropTailQueue::dequeue()
{
    if (queue.empty())
        return NULL;

   cMessage *pk = (cMessage *)queue.pop();

    // statistics
    qlenVec.record(queue.length());
    energy++;
    return pk;
}

void EnergyDropTailQueue::sendOut(cMessage *msg)
{
    send(msg, outGate);
}

void EnergyDropTailQueue::finish()
{
    PassiveQueueBase::finish();
    recordScalar("energy used by queue", energy);
}
