#ifndef _GPROBE_HELPER_GROUP_HPP
#define _GPROBE_HELPER_GROUP_HPP
#include <string>
#include <map>
#include <cinttypes>
#include <vector>
#include "gprobe_prog.hpp"

#ifdef ENABLE_GPROBE_VERIFIER
#include <gprobe-verifier.hpp>
#endif

namespace gprobe
{
struct gprobe_helper_info {
	unsigned int index;
	std::string name;
	void *fn;
};

// Checks the concrete implementation as well as the BPF helper number.
bool helper_is_async_signal_safe(unsigned index, void *fn);

class gprobe_helper_group {
    public:
	gprobe_helper_group() = default;
	gprobe_helper_group(
		std::map<unsigned int, gprobe_helper_info> helper_map)
		: helper_map(helper_map)
	{
	}
	~gprobe_helper_group() = default;

	// Register a helper
	int register_helper(const gprobe_helper_info &info);

	// Append another group to the current one
	int append(const gprobe_helper_group &another_group);

	// Utility function to get the UFUNC helper group
	static const gprobe_helper_group &get_ufunc_helper_group();

	// Utility function to get the kernel utilities helper group
	static const gprobe_helper_group &get_kernel_utils_helper_group();

	// Function to register and create a local hash map helper group
	static const gprobe_helper_group &get_shm_maps_helper_group();

	// Add the helper group to the program
	int add_helper_group_to_prog(gprobe_prog *prog) const;
	// Get all helper ids of this helper group
	std::vector<int32_t> get_helper_ids() const;

    private:
	// Map to store helpers indexed by their unique ID
	std::map<unsigned int, gprobe_helper_info> helper_map;
};
#ifdef ENABLE_GPROBE_VERIFIER
std::map<int32_t, gprobe::verifier::GprobeHelperProrotype>
get_ufunc_helper_protos();
#endif
} // namespace gprobe
#endif
