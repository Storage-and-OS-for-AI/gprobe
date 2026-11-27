#ifndef _MACA_ATTACH_PRIVATE_DATA_HPP
#define _MACA_ATTACH_PRIVATE_DATA_HPP

#include "attach_private_data.hpp"
#include "maca_attach_impl.hpp"
#include <ebpf_inst.h>
#include <vector>
#include <string>

namespace gprobe
{
namespace attach
{

struct maca_attach_private_data final : public attach_private_data {
	std::vector<std::string> func_names;
	std::string maca_source_path;
	uintptr_t comm_shared_mem = 0;
	std::vector<MapBasicInfo> map_basic_info;
	std::vector<ebpf_inst> instructions;
	std::string program_name;

	int initialize_from_string(const std::string_view &sv) override;
	std::string to_string() const override;
};

} // namespace attach
} // namespace gprobe

#endif
