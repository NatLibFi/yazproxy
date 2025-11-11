/* This file is part of YAZ proxy
   Copyright (C) 1998-2025 Index Data

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

#ifndef MOD_HELSINKI_H
#define MOD_HELSINKI_H

#include <cstdint>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#define HELSINKI_PARSE_ERANGE -999
#define HELSINKI_PARSE_EBLOCK -998
#define HELSINKI_PARSE_EMASK -997

typedef enum { IPAddress, IPAddressRange, IPAddressBlock } IPMatchKind;
struct IPBlock {
    struct sockaddr_storage address_first;
    uint8_t prefix;
};

typedef struct {
    union {
        struct sockaddr_storage address;
        struct {
            struct sockaddr_storage lo;
            struct sockaddr_storage hi;
        };
        struct IPBlock block;
    };
    IPMatchKind match_kind;
} IPMatchTarget;

bool addr_matches(const struct sockaddr_storage *peer, const IPMatchTarget *target);

int parse_match(const char *str, IPMatchTarget *dst);

int str_to_address(const char *str, struct sockaddr_storage *dst);
int str_to_address_block(const char *str, struct IPBlock *dst);

int str_to_address_range(const char *str, struct sockaddr_storage *dst_lo,
                                struct sockaddr_storage *dst_hi);
void str_trim(char *str);

int my_authenticate(void *user_handle,
                    const char *target_name,
                    void *element_ptr,
                    const char *user, const char *group, const char *password,
                    const char *peer_IP);

#endif /* MOD_HELSINKI_H */
