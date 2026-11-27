#include "catch2/catch_test_macros.hpp"
#include <base_attach_impl.hpp>
#include <catch2/catch_test_macros.hpp>
#include <cstdint>

using namespace gprobe::attach;
using namespace gprobe;

TEST_CASE("Test gprobe_set_retval")
{
	curr_thread_override_return_callback.reset();
	REQUIRE_THROWS(gprobe_set_retval(0));
	bool called = false;
	curr_thread_override_return_callback = [&](uint64_t, uint64_t) {
		called = true;
	};
	gprobe_set_retval(0);
	REQUIRE(called);
}

TEST_CASE("Test gprobe_override_return")
{
	curr_thread_override_return_callback.reset();
	REQUIRE_THROWS(gprobe_override_return(0, 0));

	bool called = false;
	curr_thread_override_return_callback = [&](uint64_t, uint64_t) {
		called = true;
	};
	gprobe_override_return(0, 0);
	REQUIRE(called);
}
