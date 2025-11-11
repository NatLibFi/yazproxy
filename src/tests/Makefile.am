check_PROGRAMS = cdetails
cdetails_SOURCES = cdetails.cpp

# Enable additional tests if Google Test is available
if HAVE_GTEST
    AM_CXXFLAGS = -I$(srcdir)/../../include $(YAZPPINC) $(USEMARCONINC)
    noinst_LTLIBRARIES = libmod_helsinki_convenience.la
    libmod_helsinki_convenience_la_SOURCES = ../mod_helsinki.cpp
    libmod_helsinki_convenience_la_LIBADD = $(YAZ_LIB) $(YAZPPLALIB) \
        $(USEMARCONLALIB)
    libmod_helsinki_convenience_la_CXXFLAGS = $(AM_CXXFLAGS)

    check_PROGRAMS += mod_helsinki_unit_test
    mod_helsinki_unit_test_LDADD = ../libyazproxy.la \
        libmod_helsinki_convenience.la $(GTEST_LIBS) -lgtest_main
    mod_helsinki_unit_test_SOURCES = mod_helsinki_unit_test.cpp
    mod_helsinki_unit_test_CXXFLAGS = $(AM_CXXFLAGS) $(GTEST_CFLAGS)
endif
#mod_helsinki_unit_test_LDFLAGS = -rpath $(pkglibdir) -avoid-version

TESTS = $(check_PROGRAMS)
