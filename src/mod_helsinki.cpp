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

#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <yazproxy/module.h>

#include <yaz/log.h>

#if YAZ_HAVE_XSLT
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xinclude.h>
#include <libxslt/transform.h>
#include <libxslt/xsltutils.h>
#endif

#include "mod_helsinki.h"

void *my_init(void)
{
    return 0; // no private data for handler
}

void my_destroy(void *p)
{
    // private data destroy
}

int str_to_address(const char *str, struct sockaddr_storage *dst)
{
    struct addrinfo hints = {}, *res = nullptr;

    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_NUMERICHOST;

    int ret = getaddrinfo(str, nullptr, &hints, &res);
    // TODO: Technically getaddrinfo() could return multiple addresses, but
    // because we have AI_NUMERICHOST, it's probably unlikely or not relevant,
    // so we only take the first one in the linked list.  That said, if we run
    // into bugs, this might be a good place to look.
    if (ret == 0 && res && res->ai_addr &&
        res->ai_addrlen <= sizeof(struct sockaddr_storage)) {
        memset(dst, 0, sizeof(struct sockaddr_storage));
        memcpy(dst, reinterpret_cast<struct sockaddr_storage *>(res->ai_addr),
               res->ai_addrlen);
    }
    if (res) {
        freeaddrinfo(res);
    }
    return ret;
}

void str_trim(char *str)
{
    size_t leading{}, trailing{}, i{};
    const size_t orig_len = strlen(str);
    for (i = 0; i < orig_len && isspace(str[i]); i++) { leading++; }
    for (i = orig_len - 1; isspace(str[i]) && i > 0; i--) { trailing++; }
    if (leading > 0) {
        memmove(str, str + leading, orig_len - leading - trailing);
    }
    str[orig_len - leading - trailing] = '\0';
}

int str_to_address_range(const char *str, struct sockaddr_storage *out_lo,
                         struct sockaddr_storage *out_hi)
{
    char *lo = nullptr, *hi = nullptr;
    char *saveptr, tmpstr[256];
    int ret;

    snprintf(tmpstr, sizeof(tmpstr), "%s", str);
    lo = strtok_r(tmpstr, "-", &saveptr);
    if (lo != nullptr) {
        hi = strtok_r(nullptr, "-", &saveptr);
    }
    if (lo == nullptr || hi == nullptr) {
        return HELSINKI_PARSE_ERANGE;
    }

    str_trim(lo);
    str_trim(hi);
    ret = str_to_address(lo, out_lo);
    if (ret != 0) {
        return ret;
    }
    ret = str_to_address(hi, out_hi);
    return ret;
}

int str_to_address_block(const char *str, struct IPBlock *dst)
{
    const char *addr_str = nullptr, *mask_str = nullptr;
    char *saveptr, *endptr, tmpstr[256];
    int ret;

    snprintf(tmpstr, sizeof(tmpstr), "%s", str);
    addr_str = strtok_r(tmpstr, "/", &saveptr);
    if (addr_str != nullptr) {
        mask_str = strtok_r(nullptr, "/", &saveptr);
    }
    if (addr_str == nullptr || mask_str == nullptr) {
        return HELSINKI_PARSE_EBLOCK;
    }
    ret = str_to_address(addr_str, &dst->address_first);
    errno = 0;
    unsigned long prefix_ul = strtoul(mask_str, &endptr, 10);
    dst->prefix = static_cast<unsigned>(prefix_ul);
    if (errno == ERANGE ||
        (dst->address_first.ss_family == AF_INET && dst->prefix > 32) ||
        dst->prefix > 128 || *endptr != '\0') {
        return HELSINKI_PARSE_EMASK;
    }
    return ret;
}

static bool addr_matches_addr(const struct sockaddr_storage *a,
                              const struct sockaddr_storage *b)
{
    if (a->ss_family != b->ss_family) {
        return false;
    }
    if (a->ss_family == AF_INET6) {
        const struct sockaddr_in6 *a_v6 =
            reinterpret_cast<const struct sockaddr_in6 *>(a);
        const struct sockaddr_in6 *b_v6 =
            reinterpret_cast<const struct sockaddr_in6 *>(b);
        if (memcmp(&(a_v6->sin6_addr.s6_addr), &(b_v6->sin6_addr.s6_addr),
                   sizeof(a_v6->sin6_addr.s6_addr)) != 0) {
            return false;
        }
    }
    else {
        const struct sockaddr_in *a_v4 =
            reinterpret_cast<const struct sockaddr_in *>(a);
        const struct sockaddr_in *b_v4 =
            reinterpret_cast<const struct sockaddr_in *>(b);
        if (a_v4->sin_addr.s_addr != b_v4->sin_addr.s_addr) {
            return false;
        }
    }
    return true;
}

static bool addr_matches_range(const struct sockaddr_storage *peer,
                               const struct sockaddr_storage *lo,
                               const struct sockaddr_storage *hi)
{
    if (peer->ss_family != lo->ss_family || peer->ss_family != hi->ss_family) {
        return false;
    }

    if (peer->ss_family == AF_INET6) {
        const struct sockaddr_in6 *peer_v6 =
            reinterpret_cast<const struct sockaddr_in6 *>(peer);
        const struct sockaddr_in6 *lo_v6 =
            reinterpret_cast<const struct sockaddr_in6 *>(lo);
        const struct sockaddr_in6 *hi_v6 =
            reinterpret_cast<const struct sockaddr_in6 *>(hi);
        const int cmp_lo =
            memcmp(&peer_v6->sin6_addr, &lo_v6->sin6_addr, sizeof(in6_addr));
        const int cmp_hi =
            memcmp(&peer_v6->sin6_addr, &hi_v6->sin6_addr, sizeof(in6_addr));
        return (cmp_lo >= 0 && cmp_hi <= 0);
    }
    else {
        const struct sockaddr_in *peer_v4 =
            reinterpret_cast<const struct sockaddr_in *>(peer);
        const struct sockaddr_in *lo_v4 =
            reinterpret_cast<const struct sockaddr_in *>(lo);
        const struct sockaddr_in *hi_v4 =
            reinterpret_cast<const struct sockaddr_in *>(hi);
        const uint32_t peer_h = ntohl(peer_v4->sin_addr.s_addr);
        const uint32_t lo_h = ntohl(lo_v4->sin_addr.s_addr);
        const uint32_t hi_h = ntohl(hi_v4->sin_addr.s_addr);
        return (peer_h >= lo_h && peer_h <= hi_h);
    }
    return true;
}

static bool match_prefix_bits(const uint8_t *a, const uint8_t *b, uint8_t bits,
                              size_t width)
{
    if (bits == 0)
        return true;

    size_t full_bytes = bits / 8;
    size_t rem_bits = bits % 8;

    if (full_bytes > 0 && memcmp(a, b, full_bytes) != 0) {
        return false;
    }
    if (rem_bits == 0) {
        // full bytes matched, no remainder bits, prefix matches
        return true;
    }
    if (full_bytes >= width) {
        // prefix mask too wide
        return false;
    }

    // build mask for last byte
    uint8_t mask = static_cast<uint8_t>((0xff << (8 - rem_bits)));

    return (a[full_bytes] & mask) == (b[full_bytes] & mask);
}

bool addr_matches_block(const struct sockaddr_storage *peer,
                        const IPBlock *block)
{
    if (peer->ss_family != block->address_first.ss_family) {
        return false;
    }
    if (peer->ss_family == AF_INET) {
        const struct sockaddr_in *peer_v4 =
            reinterpret_cast<const struct sockaddr_in *>(peer);
        const struct sockaddr_in *base =
            reinterpret_cast<const struct sockaddr_in *>(&block->address_first);
        const uint8_t *a =
            reinterpret_cast<const uint8_t *>(&peer_v4->sin_addr.s_addr);
        const uint8_t *b =
            reinterpret_cast<const uint8_t *>(&base->sin_addr.s_addr);
        return match_prefix_bits(a, b, block->prefix, 4);
    }
    else {
        const struct sockaddr_in6 *peer_v6 =
            reinterpret_cast<const struct sockaddr_in6 *>(peer);
        const struct sockaddr_in6 *base =
            reinterpret_cast<const struct sockaddr_in6 *>(
                &block->address_first);
        const uint8_t *a =
            reinterpret_cast<const uint8_t *>(&peer_v6->sin6_addr.s6_addr);
        const uint8_t *b =
            reinterpret_cast<const uint8_t *>(&base->sin6_addr.s6_addr);
        return match_prefix_bits(a, b, block->prefix, 16);
    }

    // unsupported address family?
    return false;
}

int parse_match(const char *str, IPMatchTarget *dst)
{
    if (strchr(str, '-'))
    {
        dst->match_kind = IPAddressRange;
        return str_to_address_range(str, &dst->lo, &dst->hi);
    }
    else if (strchr(str, '/')) {
        dst->match_kind = IPAddressBlock;
        return str_to_address_block(str, &dst->block);
    }
    dst->match_kind = IPAddress;
    return str_to_address(str, &dst->address);
}

bool addr_matches(const struct sockaddr_storage *peer,
                 const IPMatchTarget *target)
{
    if (target->match_kind == IPAddressRange)
    {
        return addr_matches_range(peer, &target->lo, &target->hi);
    }
    else if (target->match_kind == IPAddressBlock) {
        return addr_matches_block(peer, &target->block);
    }
    return addr_matches_addr(peer, &target->address);
}

static void int_to_warning(int code, char *buf, size_t len)
{
    switch (code) {
        case HELSINKI_PARSE_EBLOCK:
            strncpy(buf, "Bad address prefix", len);
            break;
        case HELSINKI_PARSE_ERANGE:
            strncpy(buf, "Bad address range", len);
            break;
        case HELSINKI_PARSE_EMASK:
            strncpy(buf, "Bad subnet mask", len);
            break;
        default:
            strncpy(buf, gai_strerror(code), len);
    }
}

int my_authenticate(void *user_handle,
                    const char *target_name,
                    void *element_ptr,
                    const char *user, const char *group, const char *password,
                    const char *peer_IP)
{
    // Username/password authentication has been removed
    (void) user;
    (void) group;
    (void) password;

    // see if we have an "args" attribute
    const char *args = nullptr;
    char warning[256];
#if YAZ_HAVE_XSLT
    xmlNodePtr ptr = (xmlNodePtr) element_ptr;
    struct _xmlAttr *attr;

    for (attr = ptr->properties; attr; attr = attr->next)
    {
        if (!strcmp(reinterpret_cast<const char *>(attr->name), "args") &&
            attr->children && attr->children->type == XML_TEXT_NODE)
            args = reinterpret_cast<const char *>(attr->children->content);
    }
#endif
    // args holds args (or NULL if none are provided)

    yaz_log(YLOG_LOG, "Authentication: authenticating address %s", peer_IP);

    // authentication handler
    const char *ip_file = args;

    if(!ip_file) {
        yaz_log(YLOG_WARN, "Authentication: no configured ip rules file");
        return YAZPROXY_RET_PERM;
    }

    yaz_log(YLOG_DEBUG, "Authentication: ip file: %s", ip_file);

    // Check if the IP address is listed in the file of allowed address ranges.
    // The format of the file:
    // 192.168.0.0
    // 192.168.0.100
    // 192.168.0.1-192.168.0.200
    // 192.168.0.1/24
    // (also supports IPv6)
    int status = YAZPROXY_RET_PERM;
    if (*ip_file && peer_IP)
    {
        yaz_log(YLOG_DEBUG, "Authentication: checking ip address");

        const char *pIP = peer_IP;
        if (strncmp(pIP, "tcp:", 4) == 0)
            pIP += 4;

        struct sockaddr_storage peer_address;
        int int_parse_status = str_to_address(pIP, &peer_address);
        if (int_parse_status != 0)
        {
            int_to_warning(int_parse_status, warning, sizeof(warning));
            yaz_log(YLOG_WARN,
                    "Authentication: could not decode peer IP address %s "
                    "properly: %s",
                    pIP, warning);
            return YAZPROXY_RET_PERM;
        }

        FILE *f = fopen(ip_file, "r");
        if (!f)
        {
            yaz_log(YLOG_WARN, "Authentication: could not open ip authentication file %s", ip_file);
                return YAZPROXY_RET_PERM;
        }
        char line[256];
        while (fgets(line, sizeof(line), f))
        {
            IPMatchTarget match_target;

            // Remove comments
            char *comment_pos = strchr(line, '#');
            if (comment_pos)
                *comment_pos = '\0';

            str_trim(line);
            if (strlen(line) == 0) {
                continue;
            }

            yaz_log(YLOG_DEBUG, "Authentication: comparing IP address %s against rule '%s'", pIP, line);

            int parse_status = parse_match(line, &match_target);
            if(parse_status == 0)
            {
                if (addr_matches(&peer_address, &match_target))
                {
                    status = YAZPROXY_RET_OK;
                    break;
                }
            }
            else {
                int_to_warning(parse_status, warning, sizeof(warning));
                yaz_log(YLOG_WARN,
                        "Authentication: problem parsing config line '%s': %s",
                        line,
                        warning);
            }
        }

        fclose(f);
        if (status == YAZPROXY_RET_OK)
        {
            yaz_log(YLOG_LOG, "Authentication: IP address %s allowed", pIP);
        }
    }
    return status;
}

Yaz_ProxyModule_int0 interface0 = {
    my_init,
    my_destroy,
    my_authenticate
};

Yaz_ProxyModule_entry yazproxy_module = {
    0,                            // interface version
    "helsinki",                     // name
    "Helsinki Module for YAZ Proxy",// description
    &interface0
};

/*
 * Local variables:
 * c-basic-offset: 4
 * c-file-style: "Stroustrup"
 * indent-tabs-mode: nil
 * End:
 * vim: shiftwidth=4 tabstop=8 expandtab
 */
