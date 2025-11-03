check_PROGRAMS = cdetails
cdetails_SOURCES = cdetails.cpp

# Enable additional tests if Google Test is available
if HAVE_GTEST
    check_PROGRAMS += mod_helsinki_unit_test
    mod_helsinki_unit_test_SOURCES = mod_helsinki_unit_test.cpp
    mod_helsinki_unit_test_LDADD = $(GTEST_LIBS)
    mod_helsinki_unit_test_CXXFLAGS = $(AM_CXXFLAGS) $(GTEST_CFLAGS)
endif

TESTS = $(check_PROGRAMS)
