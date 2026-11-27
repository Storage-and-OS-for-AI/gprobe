#include <gprobe_prog.hpp>
#include <gprobe_object.hpp>
#include <catch2/catch_test_macros.hpp>
#include <gprobe_helper_group.hpp>
static inline gprobe::gprobe_prog *
create_gprobe_prog(const char *name, gprobe::gprobe_object *obj)
{
	using namespace gprobe;
	gprobe_prog *prog = gprobe_object_find_program_by_name(obj, name);
	REQUIRE(prog != nullptr);
	REQUIRE(gprobe_helper_group::get_kernel_utils_helper_group()
			.add_helper_group_to_prog(prog) == 0);
	REQUIRE(prog->gprobe_prog_load(false) == 0);
	return prog;
}
