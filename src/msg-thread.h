/* $Id: msg-thread.h,v 1.3 2005-06-08 13:29:03 adam Exp $
   Copyright (c) 1998-2005, Index Data.

This file is part of the yaz-proxy.

YAZ proxy is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation; either version 2, or (at your option) any later
version.

YAZ proxy is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
for more details.

You should have received a copy of the GNU General Public License
along with YAZ proxy; see the file LICENSE.  If not, write to the
Free Software Foundation, 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.
 */

#include <pthread.h>
#include <unistd.h>
#include <ctype.h>

#if HAVE_DLFCN_H
#include <dlfcn.h>
#endif

#include <yaz++/socket-observer.h>
#include <yaz/yconfig.h>

class IMsg_Thread {
public:
    virtual IMsg_Thread *handle() = 0;
    virtual void result() = 0;
};

class Msg_Thread_Queue_List {
    friend class Msg_Thread_Queue;
 private:
    IMsg_Thread *m_item;
    Msg_Thread_Queue_List *m_next;
};

class Msg_Thread_Queue {
 public:
    Msg_Thread_Queue();
    void enqueue(IMsg_Thread *in);
    IMsg_Thread *dequeue();
    int size();
 private:
    Msg_Thread_Queue_List *m_list;
};

class Msg_Thread : public yazpp_1::ISocketObserver {
 public:
    Msg_Thread(yazpp_1::ISocketObservable *obs);
    virtual ~Msg_Thread();
    void socketNotify(int event);
    void put(IMsg_Thread *m);
    IMsg_Thread *get();
    void run(void *p);
    int m_fd[2];
private:
    yazpp_1::ISocketObservable *m_SocketObservable;
    pthread_t m_thread_id;
    Msg_Thread_Queue m_input;
    Msg_Thread_Queue m_output;
    pthread_mutex_t m_mutex_input_data;
    pthread_cond_t m_cond_input_data;
    pthread_mutex_t m_mutex_output_data;
    pthread_cond_t m_cond_output_data;
    bool m_stop_flag;
};
