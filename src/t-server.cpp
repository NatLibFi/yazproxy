/* This file is part of YAZ proxy
   Copyright (C) 1998-2011 Index Data

YAZ proxy is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation; either version 2, or (at your option) any later
version.

YAZ proxy is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include <stdlib.h>
#include <pthread.h>
#include <yaz/log.h>
#include <yaz/diagbib1.h>
#include <yaz/options.h>
#include "msg-thread.h"
#include <yazpp/z-assoc.h>
#include <yazpp/pdu-assoc.h>
#include <yazpp/gdu.h>
#include <yazpp/gduqueue.h>
#include <yazpp/socket-manager.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

using namespace yazpp_1;

class MyServer;

class Auth_Msg : public IMsg_Thread {
public:
    int m_close_flag;
    GDU *m_gdu;
    GDU *m_output;
    MyServer *m_front;
    IMsg_Thread *handle();
    void result();
    Auth_Msg(GDU *gdu, MyServer *front);
    virtual ~Auth_Msg();
};

Auth_Msg::Auth_Msg(GDU *gdu, MyServer *front)
{
    m_front = front;
    m_output = 0;
    m_gdu = gdu;
    m_close_flag = 0;
}

Auth_Msg::~Auth_Msg()
{
    delete m_output;
    delete m_gdu;
}

IMsg_Thread *Auth_Msg::handle()
{
    ODR odr = odr_createmem(ODR_ENCODE);
    yaz_log(YLOG_LOG, "Auth_Msg:handle begin");
    Z_GDU *z_gdu = m_gdu->get();
    if (z_gdu->which == Z_GDU_Z3950)
    {
        Z_APDU *apdu = 0;
        switch(z_gdu->u.z3950->which)
        {
        case Z_APDU_initRequest:
            apdu = zget_APDU(odr, Z_APDU_initResponse);
            ODR_MASK_SET(apdu->u.initResponse->options, Z_Options_triggerResourceCtrl);
            ODR_MASK_SET(apdu->u.initResponse->options, Z_Options_search);
            ODR_MASK_SET(apdu->u.initResponse->options, Z_Options_present);
            break;
        case Z_APDU_searchRequest:
#if HAVE_UNISTD_H
            sleep(5);
#endif
            apdu = zget_APDU(odr, Z_APDU_searchResponse);
            break;
        case Z_APDU_triggerResourceControlRequest:
            break;
        default:
            apdu = zget_APDU(odr, Z_APDU_close);
            m_close_flag = 1;
            break;
        }
        if (apdu)
            m_output = new GDU(apdu);
    }
    yaz_log(YLOG_LOG, "Auth_Msg:handle end");
    odr_destroy(odr);
    return this;
}

class MyServer : public Z_Assoc {
public:
    ~MyServer();
    MyServer(IPDU_Observable *the_PDU_Observable,
             Msg_Thread *m_my_thread
        );
    IPDU_Observer* sessionNotify(IPDU_Observable *the_PDU_Observable,
                                 int fd);

    void recv_GDU(Z_GDU *apdu, int len);

    void failNotify();
    void timeoutNotify();
    void connectNotify();

    int m_no_requests;
    int m_delete_flag;
private:
    yazpp_1::GDUQueue m_in_queue;
    Msg_Thread *m_my_thread;
};

void Auth_Msg::result()
{
    m_front->m_no_requests--;
    if (!m_front->m_delete_flag)
    {
        if (m_output)
        {
            int len;
            m_front->send_GDU(m_output->get(), &len);
        }
        if (m_close_flag)
        {
            m_front->close();
            m_front->m_delete_flag = 1;
        }
    }
    if (m_front->m_delete_flag && m_front->m_no_requests == 0)
        delete m_front;
    delete this;
}

MyServer::MyServer(IPDU_Observable *the_PDU_Observable,
                   Msg_Thread *my_thread
)
    :  Z_Assoc(the_PDU_Observable)
{
    m_my_thread = my_thread;
    m_no_requests = 0;
    m_delete_flag = 0;
    yaz_log(YLOG_LOG, "Construct Myserver=%p", this);
}

IPDU_Observer *MyServer::sessionNotify(IPDU_Observable
                                       *the_PDU_Observable, int fd)
{
    MyServer *my = new MyServer(the_PDU_Observable, m_my_thread);
    yaz_log(YLOG_LOG, "New session %s", the_PDU_Observable->getpeername());
    return my;
}

MyServer::~MyServer()
{
    yaz_log(YLOG_LOG, "Destroy Myserver=%p", this);
}

void MyServer::recv_GDU(Z_GDU *apdu, int len)
{
    GDU *gdu = new GDU(apdu);
    Auth_Msg *m = new Auth_Msg(gdu, this);
    m_no_requests++;
    m_my_thread->put(m);
}

void MyServer::failNotify()
{
    m_delete_flag = 1;
    if (m_no_requests == 0)
        delete this;

}

void MyServer::timeoutNotify()
{
    m_delete_flag = 1;
    if (m_no_requests == 0)
        delete this;
}

void MyServer::connectNotify()
{

}

void usage(const char *prog)
{
    fprintf (stderr, "%s: [-a log] [-v level] [-T] @:port\n", prog);
    exit (1);
}

int main(int argc, char **argv)
{
    char *arg;
    char *prog = *argv;
    int thread_flag = 0;
    int ret;
    const char *addr = "tcp:@:9999";
    char *apdu_log = 0;
    int no_threads = 1;

    while ((ret = options("n:a:v:T", argv, argc, &arg)) != -2)
    {
        switch (ret)
        {
        case 0:
            addr = xstrdup(arg);
            break;
        case 'n':
            no_threads = atoi(arg);
            break;
        case 'a':
            apdu_log = xstrdup(arg);
            break;
        case 'v':
            yaz_log_init_level (yaz_log_mask_str(arg));
            break;
        case 'T':
            thread_flag = 1;
            break;
        default:
            usage(prog);
            return 1;
        }
    }

    SocketManager mySocketManager;

    PDU_Assoc *my_PDU_Assoc = 0;

    MyServer *z = 0;

    Msg_Thread *my_thread = new Msg_Thread(&mySocketManager, no_threads);

#if YAZ_POSIX_THREADS
    if (thread_flag)
        my_PDU_Assoc = new PDU_AssocThread(&mySocketManager);
    else
        my_PDU_Assoc = new PDU_Assoc(&mySocketManager);
#else
    my_PDU_Assoc = new PDU_Assoc(&mySocketManager);
#endif

    z = new MyServer(my_PDU_Assoc, my_thread);
    z->server(addr);
    if (apdu_log)
    {
        yaz_log (YLOG_LOG, "set_APDU_log %s", apdu_log);
        z->set_APDU_log(apdu_log);
    }

    while (mySocketManager.processEvent() > 0)
        ;
    delete z;
    delete my_thread;
    return 0;
}
/*
 * Local variables:
 * c-basic-offset: 4
 * c-file-style: "Stroustrup"
 * indent-tabs-mode: nil
 * End:
 * vim: shiftwidth=4 tabstop=8 expandtab
 */

