/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022, eunomia-bpf org
 * All rights reserved.
 */
#ifndef GPROBE_JSON_EXPORTER_HPP
#define GPROBE_JSON_EXPORTER_HPP

#include <string>
#include <sstream>
#include <stdio.h>
#include <iomanip>
#include "gprobe_shm_internal.hpp"

namespace gprobe
{
static inline std::string buffer_to_hex_string(const unsigned char *buffer,
					    size_t bufferSize)
{
	std::stringstream ss;
	ss << std::hex << std::setfill('0');
	for (size_t i = 0; i < bufferSize; i++) {
		ss << std::setw(2) << static_cast<int>(buffer[i]);
	}
	return ss.str();
}

static inline int hex_string_to_buffer(const std::string &hexString,
				     unsigned char *buffer, size_t bufferSize)
{
	if (hexString.length() != bufferSize * 2) {
		return -1;
	}

	for (size_t i = 0; i < bufferSize; i++) {
		std::string byteString = hexString.substr(i * 2, 2);
		buffer[i] = static_cast<unsigned char>(
			std::stoi(byteString, nullptr, 16));
	}
    return 0;
}

int gprobe_export_shm_to_json(const gprobe_shm& shm, const char *filename);
int gprobe_import_shm_from_json(gprobe_shm& shm, const char *filename);
int gprobe_import_shm_handler_from_json(gprobe_shm &shm, int fd,
					  const char *json_string);
} // namespace gprobe
#endif // GPROBE_JSON_EXPORTER_HPP
