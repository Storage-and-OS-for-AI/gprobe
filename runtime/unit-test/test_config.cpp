#include <catch2/catch_test_macros.hpp>
#include <gprobe_config.hpp>
#include "./common_def.hpp"
#include <boost/interprocess/interprocess_fwd.hpp>
using namespace gprobe;
using namespace boost::interprocess;
static const char *SHM_NAME = "_GPROBE_CONFIG_TEST";

static std::string test_string = "aaaabbb";

static std::string test_string_2 = "aaaassssbbb";

TEST_CASE("Test gprobe runtime_config")
{
	shm_remove remover(SHM_NAME);
	managed_shared_memory mem(create_only, SHM_NAME, 20 << 20);

	runtime_config cfg;
	cfg.set_logger_output_path(test_string.c_str());
	REQUIRE(cfg.get_logger_output_path() == test_string);
	cfg.set_logger_output_path(test_string_2.c_str());
	REQUIRE(cfg.get_logger_output_path() == test_string_2);
}

TEST_CASE("Allow external maps from the environment")
{
	const char *old_value = getenv("GPROBE_ALLOW_EXTERNAL_MAPS");
	const bool was_set = old_value != nullptr;
	const std::string saved_value = was_set ? old_value : "";

	REQUIRE(setenv("GPROBE_ALLOW_EXTERNAL_MAPS", "1", 1) == 0);
	const auto cfg = construct_runtime_config_from_env();
	const int restore_result =
		was_set ? setenv("GPROBE_ALLOW_EXTERNAL_MAPS",
				 saved_value.c_str(), 1) :
			  unsetenv("GPROBE_ALLOW_EXTERNAL_MAPS");

	REQUIRE(restore_result == 0);
	REQUIRE(cfg.allow_non_buildin_map_types);
}

TEST_CASE("Select Frida's fuzzy backtracer from the environment")
{
	const char *old_value = getenv("GPROBE_FRIDA_FUZZY_BACKTRACER");
	const bool was_set = old_value != nullptr;
	const std::string saved_value = was_set ? old_value : "";

	REQUIRE(unsetenv("GPROBE_FRIDA_FUZZY_BACKTRACER") == 0);
	REQUIRE_FALSE(construct_runtime_config_from_env()
			      .enable_frida_fuzzy_backtracer);
	REQUIRE(setenv("GPROBE_FRIDA_FUZZY_BACKTRACER", "1", 1) == 0);
	REQUIRE(construct_runtime_config_from_env()
			.enable_frida_fuzzy_backtracer);

	const int restore_result =
		was_set ? setenv("GPROBE_FRIDA_FUZZY_BACKTRACER",
				 saved_value.c_str(), 1) :
			  unsetenv("GPROBE_FRIDA_FUZZY_BACKTRACER");
	REQUIRE(restore_result == 0);
}
