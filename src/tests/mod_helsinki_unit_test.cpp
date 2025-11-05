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
#include "../mod_helsinki.h"
#include "yazproxy/module.h"
#include "gtest/gtest.h"
#include <arpa/inet.h>
#include <cstring>
#include <gtest/gtest.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <netinet/in.h>
#include <sys/socket.h>

namespace {

TEST(Util, StrTrim)
{
    char leading_space[] = "   foo bar";
    char trailing_space[] = "foo bar  \t";
    char surrounding_space[] = " foo\t- bar   ";
    str_trim(leading_space);
    str_trim(trailing_space);
    str_trim(surrounding_space);
    EXPECT_STREQ(leading_space, "foo bar") << "Failed to trim leading space";
    EXPECT_STREQ(trailing_space, "foo bar") << "Failed to trim trailing space";
    EXPECT_STREQ(surrounding_space, "foo\t- bar")
        << "Failed to trim surrounding space";
}

TEST(Parse, AddressV4)
{
    const char *ip = "192.168.1.100";
    struct sockaddr_storage actual = {};
    struct sockaddr_in expected = {};
    expected.sin_family = AF_INET;

    ASSERT_EQ(inet_pton(AF_INET, ip, &expected.sin_addr), 1);

    ASSERT_EQ(str_to_address(ip, &actual), 0);

    ASSERT_EQ(actual.ss_family, AF_INET) << "Address is not IPv4";
    auto *actual_addr = reinterpret_cast<struct sockaddr_in *>(&actual);
    EXPECT_EQ(actual_addr->sin_addr.s_addr, expected.sin_addr.s_addr);
}

TEST(Parse, AddressV6)
{
    const char *ip = "2001:14ba:b1:5c00:7d96:a266:b594:235a";
    struct sockaddr_storage actual = {};
    struct sockaddr_in6 expected = {};
    expected.sin6_family = AF_INET6;

    ASSERT_EQ(inet_pton(AF_INET6, ip, &expected.sin6_addr), 1);

    ASSERT_EQ(str_to_address(ip, &actual), 0);

    ASSERT_EQ(actual.ss_family, AF_INET6) << "Address is not IPv6";
    auto *actual_addr = reinterpret_cast<struct sockaddr_in6 *>(&actual);
    EXPECT_EQ(
        memcmp(&actual_addr->sin6_addr, &expected.sin6_addr, sizeof(in6_addr)),
        0)
        << "IPv6 addresses don't match";
}

TEST(Parse, AddressV4WithPrefix)
{
    const char *input = "198.51.100.20/24";
    struct IPBlock prefix;
    struct sockaddr_in expected = {};
    expected.sin_family = AF_INET;
    ASSERT_EQ(inet_pton(AF_INET, "198.51.100.20", &expected.sin_addr), 1);
    ASSERT_EQ(str_to_address_block(input, &prefix), 0);
    auto *actual =
        reinterpret_cast<struct sockaddr_in *>(&prefix.address_first);
    EXPECT_EQ(actual->sin_addr.s_addr, expected.sin_addr.s_addr)
        << "Addresses don't match";
    EXPECT_EQ(prefix.prefix, 24) << "Address prefixes don't match";
}

TEST(Parse, AddressV6WithPrefix)
{
    const char *input = "2001:14ba:b1::/48";
    struct IPBlock prefix;
    struct sockaddr_in6 expected = {};
    expected.sin6_family = AF_INET6;
    ASSERT_EQ(inet_pton(AF_INET6, "2001:14ba:b1::", &expected.sin6_addr), 1);
    ASSERT_EQ(str_to_address_block(input, &prefix), 0);
    auto *actual =
        reinterpret_cast<struct sockaddr_in6 *>(&prefix.address_first);
    EXPECT_EQ(memcmp(&actual->sin6_addr, &expected.sin6_addr, sizeof(in6_addr)),
              0)
        << "IPv6 addresses don't match";
    EXPECT_EQ(prefix.prefix, 48) << "Address prefixes don't match";
}

TEST(Parse, Range)
{
    const char *range1 = "192.168.1.100-192.168.1.200";
    struct sockaddr_storage lo_actual = {}, hi_actual = {};
    struct sockaddr_in lo_expected = {}, hi_expected = {};
    lo_expected.sin_family = AF_INET;
    hi_expected.sin_family = AF_INET;
    ASSERT_EQ(inet_pton(AF_INET, "192.168.1.100", &lo_expected.sin_addr), 1);
    ASSERT_EQ(inet_pton(AF_INET, "192.168.1.200", &hi_expected.sin_addr), 1);

    str_to_address_range(range1, &lo_actual, &hi_actual);
    auto *lo_actual_addr = reinterpret_cast<struct sockaddr_in *>(&lo_actual);
    auto *hi_actual_addr = reinterpret_cast<struct sockaddr_in *>(&hi_actual);
    EXPECT_EQ(lo_actual_addr->sin_addr.s_addr, lo_expected.sin_addr.s_addr);
    EXPECT_EQ(hi_actual_addr->sin_addr.s_addr, hi_expected.sin_addr.s_addr);
}

TEST(Parse, RangeWithWhitespace)
{
    const char *range1 = " 192.168.1.100\t- 192.168.1.200";
    struct sockaddr_storage lo_actual = {}, hi_actual = {};
    struct sockaddr_in lo_expected = {}, hi_expected = {};
    lo_expected.sin_family = AF_INET;
    hi_expected.sin_family = AF_INET;
    ASSERT_EQ(inet_pton(AF_INET, "192.168.1.100", &lo_expected.sin_addr), 1);
    ASSERT_EQ(inet_pton(AF_INET, "192.168.1.200", &hi_expected.sin_addr), 1);

    str_to_address_range(range1, &lo_actual, &hi_actual);
    auto *lo_actual_addr = reinterpret_cast<struct sockaddr_in *>(&lo_actual);
    auto *hi_actual_addr = reinterpret_cast<struct sockaddr_in *>(&hi_actual);
    EXPECT_EQ(lo_actual_addr->sin_addr.s_addr, lo_expected.sin_addr.s_addr);
    EXPECT_EQ(hi_actual_addr->sin_addr.s_addr, hi_expected.sin_addr.s_addr);
}

TEST(Parse, EmptyInput)
{
    IPMatchTarget tgt;
    ASSERT_NE(parse_match("", &tgt), 0);
}

TEST(Match, All)
{
    struct sockaddr_storage test = {};
    IPMatchTarget tgt = {};

    /* match IPv4 address */
    const char *ipv4 = "198.51.100.120";
    test.ss_family = AF_INET;
    ASSERT_EQ(
        inet_pton(AF_INET, "198.51.100.120",
                  &reinterpret_cast<struct sockaddr_in *>(&test)->sin_addr),
        1);
    ASSERT_EQ(test.ss_family, AF_INET);
    ASSERT_EQ(parse_match(ipv4, &tgt), 0);
    EXPECT_TRUE(addr_matches(&test, &tgt));

    /* match IPv6 address block */
    const char *ipv6_block = "2001:14ba:b1::/64";
    test.ss_family = AF_INET6;
    ASSERT_EQ(
        inet_pton(AF_INET6, "2001:14ba:b1::ab:cd",
                  &reinterpret_cast<struct sockaddr_in6 *>(&test)->sin6_addr),
        1);
    ASSERT_EQ(test.ss_family, AF_INET6);
    ASSERT_EQ(parse_match(ipv6_block, &tgt), 0);
    EXPECT_TRUE(addr_matches(&test, &tgt));

    /* match IPv6 address range */
    const char *ipv6_range = "2001:14ba:b1:: - 2001:14ba:b1:60::ff";
    test.ss_family = AF_INET6;
    ASSERT_EQ(
        inet_pton(AF_INET6, "2001:14ba:b1::12:34",
                  &reinterpret_cast<struct sockaddr_in6 *>(&test)->sin6_addr),
        1);
    ASSERT_EQ(test.ss_family, AF_INET6);
    ASSERT_EQ(parse_match(ipv6_range, &tgt), 0);
    EXPECT_TRUE(addr_matches(&test, &tgt));
}

TEST(NoMatch, All)
{
    struct sockaddr_storage test = {};
    IPMatchTarget tgt = {};

    /* match IPv4 address */
    const char *ipv4 = "198.51.100.120";
    test.ss_family = AF_INET;
    ASSERT_EQ(
        inet_pton(AF_INET, "198.51.100.130",
                  &reinterpret_cast<struct sockaddr_in *>(&test)->sin_addr),
        1);
    ASSERT_EQ(parse_match(ipv4, &tgt), 0);
    EXPECT_FALSE(addr_matches(&test, &tgt));

    /* match IPv4 address range */
    const char *ipv4_range = "198.51.100.1 - 198.51.100.50";
    test.ss_family = AF_INET;
    ASSERT_EQ(
        inet_pton(AF_INET, "198.51.100.60",
                  &reinterpret_cast<struct sockaddr_in *>(&test)->sin_addr),
        1);
    ASSERT_EQ(parse_match(ipv4_range, &tgt), 0);
    EXPECT_FALSE(addr_matches(&test, &tgt));

    /* match IPv6 address block */
    const char *ipv6_block = "2001:14ba:b1::/64";
    test.ss_family = AF_INET6;
    ASSERT_EQ(
        inet_pton(AF_INET6, "2001:14ba:e1::",
                  &reinterpret_cast<struct sockaddr_in6 *>(&test)->sin6_addr),
        1);
    ASSERT_EQ(parse_match(ipv6_block, &tgt), 0);
    EXPECT_FALSE(addr_matches(&test, &tgt));

    /* match IPv6 address range */
    const char *ipv6_range = "2001:14ba:b1:: - 2001:14ba:b1:60::ff";
    test.ss_family = AF_INET6;
    ASSERT_EQ(
        inet_pton(AF_INET6, "2001:14ba:d1::12:34",
                  &reinterpret_cast<struct sockaddr_in6 *>(&test)->sin6_addr),
        1);
    ASSERT_EQ(parse_match(ipv6_range, &tgt), 0);
    EXPECT_FALSE(addr_matches(&test, &tgt));
}

struct AuthTestParam {
    const char *peer_ip;
    int expected_ret;
};

class AuthIpRulesFixture : public ::testing::TestWithParam<AuthTestParam> {
  protected:
    xmlDocPtr doc_ = nullptr;
    xmlNodePtr root_ = nullptr;

    void SetUp() override
    {
#if YAZ_HAVE_XSLT
        xmlInitParser();
        const char *xml = "<client-authentication module=\"helsinki\""
                          " args=\"fixtures/iprules\"/>";
        xmlDocPtr doc = xmlReadMemory(xml, strlen(xml), "in-memory.xml",
                                      nullptr, XML_PARSE_NONET);
        ASSERT_NE(doc, nullptr);

        root_ = xmlDocGetRootElement(doc);
        ASSERT_NE(root_, nullptr);
        ASSERT_STREQ(reinterpret_cast<const char *>(root_->name),
                     "client-authentication");
#else
        GTEST_SKIP() << "YAZ_HAVE_XSLT not defined";
#endif
    }

    void TearDown() override
    {
        if (doc_)
            xmlFreeDoc(doc_);
    }
};

TEST_P(AuthIpRulesFixture, Success)
{
#if YAZ_HAVE_XSLT
    const auto &p = GetParam();
    int ret = my_authenticate(nullptr, nullptr, root_, nullptr, nullptr,
                              nullptr, p.peer_ip);
    ASSERT_EQ(ret, p.expected_ret)
        << "IP authentication failed for " << p.peer_ip;
#endif
}

INSTANTIATE_TEST_SUITE_P(
    Authenticate,
    AuthIpRulesFixture,
    ::testing::Values(
        AuthTestParam{"198.51.100.2", YAZPROXY_RET_OK},
        AuthTestParam{"198.51.100.50", YAZPROXY_RET_OK},
        AuthTestParam{"10.0.0.25", YAZPROXY_RET_PERM},
        AuthTestParam{"198.51.100.30", YAZPROXY_RET_PERM},
        AuthTestParam{"2001:14ba:d1::12:34", YAZPROXY_RET_PERM}
    )
);

} // namespace
/*
 * Local variables:
 * c-basic-offset: 4
 * c-file-style: "Stroustrup"
 * indent-tabs-mode: nil
 * End:
 * vim: shiftwidth=4 tabstop=8 expandtab
 */
