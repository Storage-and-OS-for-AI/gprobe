/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022, eunomia-bpf org
 * All rights reserved.
 */
#include <handler/epoll_handler.hpp>
#if __linux__
#include <sys/epoll.h>
#elif __APPLE__
#include "gprobe_epoll.h"
#endif
namespace gprobe
{
epoll_handler::epoll_handler(boost::interprocess::managed_shared_memory &memory)
	: files(memory.get_segment_manager())

{
	epoll_event ev;
}

epoll_file::epoll_file(const file_ptr_variant &&ptr)
	: epoll_file(std::move(ptr), epoll_data_t{ .u64 = 0 })
{
}
epoll_file::epoll_file(const file_ptr_variant &&ptr, epoll_data_t data)
	: file(ptr), data(data)
{
}

} // namespace gprobe
