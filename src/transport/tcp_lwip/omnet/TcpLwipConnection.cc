//
// Copyright (C) 2010 Zoltan Bojthe
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
//


#include "TcpLwipConnection.h"

#include "headers/defs.h"   // for endian macros
#include "IPControlInfo.h"
#include "IPv6ControlInfo.h"
#include "headers/tcp.h"
#include "lwip/tcp.h"
#include "TCP_lwip.h"
#include "TcpLwipQueues.h"
#include "TCPCommand_m.h"
#include "TCPIPchecksum.h"
#include "TCPSegment.h"
#include "TCPSerializer.h"

#include <assert.h>
#include <dlfcn.h>

// macro for normal ev<< logging (note: deliberately no parens in macro def)
#define tcpEV (ev.disable_tracing||TCP_lwip::testingS) ? ev : ev


TcpLwipConnection::Stats::Stats()
:
    sndWndVector("send window"),
    sndSeqVector("sent seq"),
    sndAckVector("sent ack"),
    sndSacksVector("sent sacks"),

    rcvWndVector("receive window"),
    rcvSeqVector("rcvd seq"),
    rcvAdvVector("advertised window"),
    rcvAckVector("rcvd ack"),
    rcvSacksVector("rcvd sacks"),

    unackedVector("unacked bytes"),

    dupAcksVector("rcvd dupAcks"),
    pipeVector("pipe"),
    rcvOooSegVector("rcvd oooseg"),

    sackedBytesVector("rcvd sackedBytes"),
    tcpRcvQueueBytesVector("tcpRcvQueueBytes"),
    tcpRcvQueueDropsVector("tcpRcvQueueDrops")
{
}

TcpLwipConnection::Stats::~Stats()
{
}

void TcpLwipConnection::Stats::recordSend(const TCPSegment &tcpsegP)
{
    sndWndVector.record(tcpsegP.getWindow());
    sndSeqVector.record(tcpsegP.getSequenceNo());
    if (tcpsegP.getAckBit())
        sndAckVector.record(tcpsegP.getAckNo());
}

void TcpLwipConnection::Stats::recordReceive(const TCPSegment &tcpsegP)
{
    rcvWndVector.record(tcpsegP.getWindow());
    rcvSeqVector.record(tcpsegP.getSequenceNo());
    if (tcpsegP.getAckBit())
        rcvAckVector.record(tcpsegP.getAckNo());
}


TcpLwipConnection::TcpLwipConnection(TCP_lwip &tcpLwipP, int connIdP, int gateIndexP, TCPDataTransferMode dataTransferModeP)
    :
    connIdM(connIdP),
    appGateIndexM(gateIndexP),
    pcbM(NULL),
    sendQueueM(tcpLwipP.createSendQueue(dataTransferModeP)),
    receiveQueueM(tcpLwipP.createReceiveQueue(dataTransferModeP)),
    tcpLwipM(tcpLwipP),
    totalSentM(0),
    isListenerM(false),
    onCloseM(false),
    statsM(NULL)
{
    pcbM = tcpLwipM.getLwipTcpLayer()->tcp_new();
    ASSERT(pcbM);

    pcbM->callback_arg = this;

    sendQueueM->setConnection(this);
    receiveQueueM->setConnection(this);
    if(tcpLwipM.recordStatisticsM)
        statsM = new Stats();
}

TcpLwipConnection::TcpLwipConnection(TcpLwipConnection &connP, int connIdP, LwipTcpLayer::tcp_pcb *pcbP)
    :
    connIdM(connIdP),
    appGateIndexM(connP.appGateIndexM),
    pcbM(pcbP),
    sendQueueM(check_and_cast<TcpLwipSendQueue *>(createOne(connP.sendQueueM->getClassName()))),
    receiveQueueM(check_and_cast<TcpLwipReceiveQueue *>(createOne(connP.receiveQueueM->getClassName()))),
    tcpLwipM(connP.tcpLwipM),
    totalSentM(0),
    isListenerM(false),
    onCloseM(false),
    statsM(NULL)
{
    pcbM = pcbP;
    pcbM->callback_arg = this;

    // Get other TCPOpenCommand parameters
    explicitReadsEnabledM = connP.explicitReadsEnabledM;
    sendNotificationsEnabledM = connP.sendNotificationsEnabledM;
    sendingObjectUpAtFirstByteEnabledM = connP.sendingObjectUpAtFirstByteEnabledM;
    receiveBufferSizeM = connP.receiveBufferSizeM;
    readBytesM = 0;
    unRecvedM = 0;

    sendQueueM->setConnection(this);
    receiveQueueM->setConnection(this);
    if(tcpLwipM.recordStatisticsM)
        statsM = new Stats();
}

TcpLwipConnection::~TcpLwipConnection()
{
    if(pcbM)
        pcbM->callback_arg = NULL;

    tcpEV << "~TcpLwipConnection()[connId:" << connIdM << "]: receiveQueue:" << receiveQueueM->getExtractableBytesUpTo()
            << ", sendQueue:" << sendQueueM->getBytesAvailable()
            << ", unRecved:" << unRecvedM
            << endl;

    delete receiveQueueM;
    delete sendQueueM;
    delete statsM;
}

void TcpLwipConnection::sendEstablishedMsg()
{
    cMessage *msg = new cMessage("TCP_I_ESTABLISHED");
    msg->setKind(TCP_I_ESTABLISHED);

    TCPConnectInfo *tcpConnectInfo = new TCPConnectInfo();

    IPvXAddress localAddr(pcbM->local_ip.addr), remoteAddr(pcbM->remote_ip.addr);

    tcpConnectInfo->setConnId(connIdM);
    tcpConnectInfo->setLocalAddr(localAddr);
    tcpConnectInfo->setRemoteAddr(remoteAddr);
    tcpConnectInfo->setLocalPort(pcbM->local_port);
    tcpConnectInfo->setRemotePort(pcbM->remote_port);

    msg->setControlInfo(tcpConnectInfo);

    sendToApp(msg);
}

const char *TcpLwipConnection::indicationName(int code)
{
#define CASE(x) case x: s=#x+6; break
    const char *s = "unknown";
    switch (code)
    {
        CASE(TCP_I_DATA);
        CASE(TCP_I_DATA_ARRIVED);
        CASE(TCP_I_DATA_SENT);
        CASE(TCP_I_URGENT_DATA);
        CASE(TCP_I_ESTABLISHED);
        CASE(TCP_I_PEER_CLOSED);
        CASE(TCP_I_CLOSED);
        CASE(TCP_I_CONNECTION_REFUSED);
        CASE(TCP_I_CONNECTION_RESET);
        CASE(TCP_I_TIMED_OUT);
        CASE(TCP_I_STATUS);
    }
    return s;
#undef CASE
}

void TcpLwipConnection::sendIndicationToApp(int code)
{
    tcpEV << "Notifying app: " << indicationName(code) << "\n";
    cMessage *msg = new cMessage(indicationName(code));
    msg->setKind(code);
    TCPCommand *ind = new TCPCommand();
    ind->setConnId(connIdM);
    msg->setControlInfo(ind);
    sendToApp(msg);
}

void TcpLwipConnection::fillStatusInfo(TCPStatusInfo &statusInfo)
{
//TODO    statusInfo.setState(fsm.getState());
//TODO    statusInfo.setStateName(stateName(fsm.getState()));

    statusInfo.setLocalAddr(IPvXAddress((pcbM->local_ip.addr)));
    statusInfo.setLocalPort(pcbM->local_port);
    statusInfo.setRemoteAddr(IPvXAddress((pcbM->remote_ip.addr)));
    statusInfo.setRemotePort(pcbM->remote_port);

    statusInfo.setSnd_mss(pcbM->mss);
//TODO    statusInfo.setSnd_una(pcbM->snd_una);
    statusInfo.setSnd_nxt(pcbM->snd_nxt);
//TODO    statusInfo.setSnd_max(pcbM->snd_max);
    statusInfo.setSnd_wnd(pcbM->snd_wnd);
//TODO    statusInfo.setSnd_up(pcbM->snd_up);
    statusInfo.setSnd_wl1(pcbM->snd_wl1);
    statusInfo.setSnd_wl2(pcbM->snd_wl2);
//TODO    statusInfo.setIss(pcbM->iss);
    statusInfo.setRcv_nxt(pcbM->rcv_nxt);
    statusInfo.setRcv_wnd(pcbM->rcv_wnd);
//TODO    statusInfo.setRcv_up(pcbM->rcv_up);
//TODO    statusInfo.setIrs(pcbM->irs);
//TODO    statusInfo.setFin_ack_rcvd(pcbM->fin_ack_rcvd);
}

void TcpLwipConnection::listen(TCPOpenCommand &tcpCommand)
{
    unsigned short localPort = tcpCommand.getLocalPort();
    onCloseM = false;
    tcpLwipM.getLwipTcpLayer()->tcp_bind(pcbM, NULL, localPort);

    // Get other TCPOpenCommand parameters
    explicitReadsEnabledM = tcpCommand.getExplicitReadsEnabled();
    sendNotificationsEnabledM = tcpCommand.getSendNotificationsEnabled();
    sendingObjectUpAtFirstByteEnabledM = tcpCommand.getSendingObjectUpAtFirstByteEnabled();
    receiveBufferSizeM = tcpCommand.getReceiveBufferSize();
    readBytesM = 0;
    unRecvedM = 0;

    // IMPORTANT!!! unlink old pcb from this object, otherwise lwip_free_pcb_event destroy this conn.
    LwipTcpLayer::tcp_pcb *pcb = pcbM;
    pcbM = NULL;
    // IMPORTANT!!! unlink old pcb from this object, otherwise lwip_free_pcb_event destroy this conn.

    pcbM = tcpLwipM.getLwipTcpLayer()->tcp_listen(pcb);
    totalSentM = 0;
}

void TcpLwipConnection::connect(TCPOpenCommand &tcpCommand)
{
    // IPvXAddress& localAddr = tcpCommand.getLocalAddr();
    // unsigned short localPort = tcpCommand.getLocalPort();
    IPvXAddress& remoteAddr = tcpCommand.getRemoteAddr();
    unsigned short remotePort = tcpCommand.getRemotePort();

    // Get other TCPOpenCommand parameters
    explicitReadsEnabledM = tcpCommand.getExplicitReadsEnabled();
    sendNotificationsEnabledM = tcpCommand.getSendNotificationsEnabled();
    sendingObjectUpAtFirstByteEnabledM = tcpCommand.getSendingObjectUpAtFirstByteEnabled();
    receiveBufferSizeM = tcpCommand.getReceiveBufferSize();
    readBytesM = 0;
    unRecvedM = 0;

    onCloseM = false;
    struct ip_addr dest_addr;
    dest_addr.addr = remoteAddr;
    tcpLwipM.getLwipTcpLayer()->tcp_connect(pcbM, &dest_addr, (u16_t)remotePort, NULL);
    totalSentM = 0;
}

void TcpLwipConnection::process_CLOSE()
{
    onCloseM = true;
    if (0 == sendQueueM->getBytesAvailable())
    {
        tcpLwipM.getLwipTcpLayer()->tcp_close(pcbM);
        onCloseM = false;
    }
}

void TcpLwipConnection::process_ABORT()
{
    tcpLwipM.getLwipTcpLayer()->tcp_close(pcbM);
    onCloseM = false;
}

void TcpLwipConnection::process_SEND(cPacket *msgP)
{
    sendQueueM->enqueueAppData(msgP);
    if (sendNotificationsEnabledM)
    {
        dataSent(0);
    }
}

void TcpLwipConnection::process_READ(TCPReadCommand &tcpCommandP)
{
    if (!explicitReadsEnabledM)
        opp_error("Invalid READ command: explicit read not enabled");

    if (readBytesM)
        opp_error("Duplicate READ command: connection already reading");

    readBytesM = tcpCommandP.getBytes();
    sendDataToApp(); //send data to APP if available
}

void TcpLwipConnection::notifyAboutSending(const TCPSegment& tcpsegP)
{
    receiveQueueM->notifyAboutSending(&tcpsegP);
    if (statsM)
        statsM->recordSend(tcpsegP);
}

int TcpLwipConnection::send_data(void *data, int datalen)
{
    int error;
    int written = 0;

    if (datalen > 0xFFFF)
      datalen = 0xFFFF; // tcp_write() length argument is uint16_t

    u32_t ss = pcbM->snd_lbb;
    error = tcpLwipM.getLwipTcpLayer()->tcp_write(pcbM, data, datalen, 1);
    if(error == ERR_OK)
    {
        written = datalen;
    }
    else if(error == ERR_MEM)
    {
        // Chances are that datalen is too large to fit in the send
        // buffer. If it is really large (larger than a typical MSS,
        // say), we should try segmenting the data ourselves.

        while(1)
        {
            u16_t snd_buf = pcbM->snd_buf;
            if(0 == snd_buf)
                break;
            if(datalen < snd_buf)
                break;
            error = tcpLwipM.getLwipTcpLayer()->tcp_write(
                    pcbM, ((const char *)data) + written, snd_buf, 1);
            if(error != ERR_OK)
                break;
            written += snd_buf;
            datalen -= snd_buf;
        }

    }
    if(written > 0)
    {
        ASSERT(pcbM->snd_lbb - ss == (u32_t)written);
        return written;
    }
    return error;
}

void TcpLwipConnection::do_SEND()
{
    char buffer[8*536];
    int bytes;
    int allsent = 0;

    while(0 != (bytes = sendQueueM->getBytesForTcpLayer(buffer, sizeof(buffer))))
    {
        int sent = send_data(buffer, bytes);

        if(sent > 0)
        {
            sendQueueM->dequeueTcpLayerMsg(sent);
            allsent += sent;
        }
        else
        {
            tcpEV << "TCP_lwip connection: " << connIdM << ": Error do sending, err is " << sent << "\n";
            break;

        }
    }

    totalSentM += allsent;
    tcpEV << "do_SEND(): " << connIdM <<
            " send:" << allsent <<
            ", unsent:" << sendQueueM->getBytesAvailable() <<
            ", total sent:" << totalSentM <<
            ", all bytes:" << totalSentM+sendQueueM->getBytesAvailable() <<
            "\n";
    if (onCloseM && (0 == sendQueueM->getBytesAvailable()))
    {
        tcpLwipM.getLwipTcpLayer()->tcp_close(pcbM);
        onCloseM = false;
    }
}

void TcpLwipConnection::sendToApp(cMessage *msg)
{
    tcpLwipM.send(msg, "appOut", appGateIndexM);
}

void TcpLwipConnection::sendDataToApp()
{
    if (explicitReadsEnabledM)
    {
        if (readBytesM)
        {
            cPacket *msg = receiveQueueM->extractBytesUpTo(readBytesM);
            if (msg)
            {
                readBytesM = 0;
                if (unRecvedM)
                {
                    u16_t len = std::min(0x7FFFUL,std::min(unRecvedM, (ulong)msg->getByteLength()));
                    tcpLwipM.getLwipTcpLayer()->tcp_recved(pcbM, len);
                    unRecvedM -= len;
                }
                sendToApp(msg);
            }
        }
        long readableBytes = receiveQueueM->getExtractableBytesUpTo();
        if (readableBytes > 0)
        {
            cMessage* info = new cMessage("DataArrived");
            info->setKind(TCP_I_DATA_ARRIVED);
            TCPDataArrivedInfo *cmd = new TCPDataArrivedInfo();
            cmd->setConnId(connIdM);
            cmd->setAvailableBytesInReceiveQueue(readableBytes);
            info->setControlInfo(cmd);
            sendToApp(info);
        }
    }
    else
    {
        while (1)
        {
            cPacket *msg = receiveQueueM->extractBytesUpTo(receiveQueueM->getExtractableBytesUpTo());
            if(msg == NULL)
                break;
            sendToApp(msg);
        }
    }
}

void TcpLwipConnection::dataSent(unsigned int sentBytesP)
{
    if (sentBytesP)
        sendQueueM->discardAckedBytes(sentBytesP);

    if (sendNotificationsEnabledM)
    {
        cMessage *msg = new cMessage("DataSent");
        // Send up a DATA sent notification
        msg->setKind(TCP_I_DATA_SENT);
        TCPDataSentInfo *cmd = new TCPDataSentInfo();
        cmd->setConnId(connIdM);
        cmd->setAvailableBytesInSendQueue(this->sendQueueM->getBytesAvailable() + (TCP_SND_BUF - pcbM->snd_buf)); //the sendQueueM length + lwip sendqueue length
        cmd->setSentBytes(sentBytesP);
        msg->setControlInfo(cmd);
        sendToApp(msg);
    }
}

err_t TcpLwipConnection::eventRecv(struct pbuf *p, err_t err)
{
    if(p == NULL)
    {
        // Received FIN:
        tcpEV << ": eventRecv(" << connIdM << ", pbuf[NULL], " << (int)err << "):FIN\n";
        sendIndicationToApp((pcbM->state == LwipTcpLayer::TIME_WAIT)
                ? TCP_I_CLOSED : TCP_I_PEER_CLOSED);
        // TODO is it good?
        tcpLwipM.getLwipTcpLayer()->tcp_recved(pcbM, 0);
    }
    else
    {
        tcpEV << ": eventRecv(" << connIdM << ", pbuf[" << p->len << ", " << p->tot_len << "], " << (int)err << ")\n";

        u16_t len = p->tot_len;
        receiveQueueM->enqueueTcpLayerData(p->payload, len);
        if (isExplicitReadsEnabled())
        {
            uint32 bytesInBuffer = receiveQueueM->getAmountOfBufferedBytes();
            uint32 bufferSize = getReceiveBufferSize();
            uint32 freeBuffer = (bytesInBuffer < bufferSize) ? bufferSize - bytesInBuffer : 0;
            if (len > freeBuffer) // if buffers has enough free bytes for this data
                len = freeBuffer;
        }
        tcpLwipM.getLwipTcpLayer()->tcp_recved(pcbM, len);
        unRecvedM += p->tot_len - len;
        pbuf_free(p);
    }

    sendDataToApp();
    do_SEND();
    return err;
}