#include "rocm_attach_private_data.hpp"
#include "spdlog/spdlog.h"
#include <sstream>

namespace gprobe
{
namespace attach
{

int rocm_attach_private_data::initialize_from_string(
	const std::string_view &sv)
{
	func_names.clear();
	if (!sv.empty())
		func_names.emplace_back(sv);
	return 0;
}

std::string rocm_attach_private_data::to_string() const
{
	std::ostringstream oss;
	oss << "rocm_attach_private_data{";
	oss << "program_name=" << program_name;
	oss << ", func_names=[";
	for (size_t i = 0; i < func_names.size(); ++i) {
		if (i > 0)
			oss << ",";
		oss << func_names[i];
	}
	oss << "]";
	oss << ", hip_source_path=" << hip_source_path;
	oss << ", instructions_count=" << instructions.size();
	oss << "}";
	return oss.str();
}

} // namespace attach
} // namespace gprobe