#include <cstring>
#include "PePatchX64.hpp"
#include "PeStructs.hpp"

namespace PeEpIntercept {
    PePatchX64::PePatchX64(std::string &path) : PePatch(path) {
        const auto *raw_buffer = file_buffer.data();
        uint32_t first_section = 0;

        if (type == PeArch::x64) {
            auto nt_header = (NtHeaderX64Ptr) &raw_buffer[dos_header.e_lfanew];
            file_header = *(CoffHeaderPtr) &nt_header->coff;
            first_section = dos_header.e_lfanew + sizeof(NtHeaderX64);
            nt_header_signature = nt_header->signature;
            optional_header = *(OptionalHeaderX64Ptr) &nt_header->optional;
        }

        if (nt_header_signature != 0x4550) {
            throw std::runtime_error("This is not a portable executable");
        }

        original_entry_point = optional_header.AddressOfEntryPoint;

        for (uint32_t i = 0; i < file_header.NumberOfSections; i++) {
            uint32_t section_index = i * sizeof(SectionHeader);
            uint32_t next_section = first_section + section_index;
            auto hdr = *(SectionHeaderPtr) &raw_buffer[next_section];
            section_headers.push_back(hdr);

            // Make a copy of the first n bytes of each section
            auto raw_data_offset = hdr.PointerToRawData;
            auto raw_data_size = hdr.SizeOfRawData;
            uint32_t bytes = (raw_data_size < 100) ? raw_data_size : 100;
            auto start = file_buffer.begin() + raw_data_offset;
            auto end = start + bytes;

            std::vector<char> section_bytes;
            section_bytes.assign(start, end);
        }

        auto rest_of_data = first_section;
        auto count = static_cast<uint32_t>(section_headers.size());
        rest_of_data += count * sizeof(SectionHeader);

        // Excludes headers since we already have the initialised structs
        auto data_start = file_buffer.begin() + rest_of_data;
        this->file_buffer.assign(data_start, file_buffer.end());
    }

    void PePatchX64::AddSection(const std::string &name, uint32_t code_size) {
        auto last_section = section_headers.back();
        auto aligned_size = Align(code_size, optional_header.FileAlignment);
        SectionHeader new_section{};

        new_section.Characteristics = characteristics;
        new_section.SizeOfRawData = aligned_size;
        new_section.Misc.VirtualSize = Align(
                aligned_size,
                optional_header.SectionAlignment);
        auto new_pointer_to_raw_data = Align(
                last_section.SizeOfRawData + last_section.PointerToRawData,
                optional_header.FileAlignment);

        // Sanity check that the new section's raw data does not overwrite
        for (auto header : section_headers) {
            auto existing_pointer = header.PointerToRawData;

            if (new_pointer_to_raw_data == existing_pointer) {
                // Remove reinterpret
                std::string section_name = reinterpret_cast<char *>(header.Name);
                throw std::runtime_error(
                        "Cannot create new section. Section, \""
                        + section_name + "\" already has that starting offset.");
            }
        }

        new_section.PointerToRawData = new_pointer_to_raw_data;
        new_section.VirtualAddress = Align(
                last_section.Misc.VirtualSize + last_section.VirtualAddress,
                optional_header.SectionAlignment);

        for (size_t i = 0; i < section_name_size; i++) {
            char letter;

            if (i < name.length()) {
                letter = name.at(i);
            } else {
                letter = '\0';
            }

            new_section.Name[i] = static_cast<uint8_t>(letter);
        }

        file_header.NumberOfSections++;
        optional_header.AddressOfEntryPoint = new_section.VirtualAddress;
        optional_header.SizeOfImage =
                new_section.VirtualAddress + new_section.Misc.VirtualSize;
        new_section_header = new_section;
    }

    void PePatchX64::SaveFile(std::string new_path, std::vector<char> code_buffer) {
        if (code_buffer.empty()) {
            throw std::runtime_error("Unable to write empty code section");
        }

        char dos_bytes[sizeof(dos_header)];
        memcpy(dos_bytes, &dos_header, sizeof(dos_header));
        file_input.seekp(0);
        file_input.write(dos_bytes, sizeof(dos_header));

        NtHeaderX64 nt_headers {
                nt_header_signature,
                file_header,
                optional_header
        };

        char nt_bytes[sizeof(nt_headers)];
        memcpy(nt_bytes, &nt_headers, sizeof(nt_headers));
        file_input.seekp(dos_header.e_lfanew);
        file_input.write(nt_bytes, sizeof(nt_headers));
        uint32_t section = dos_header.e_lfanew + sizeof(nt_headers);

        for (auto &section_header : section_headers) {
            char hdr_bytes[sizeof(section_header)];
            memcpy(hdr_bytes, &section_header, sizeof(section_header));
            file_input.seekp(section);
            file_input.write(hdr_bytes, sizeof(section_header));
            section += sizeof(section_header);
        }

        uint32_t code_position = new_section_header.PointerToRawData;

        file_input.seekp(code_position);

        // Padding might be required otherwise the loader will fail
        // when loading the executable
        while (code_buffer.size() < new_section_header.SizeOfRawData) {
            code_buffer.push_back(0);
        }

        file_input.write(code_buffer.data(), code_buffer.size());

        // The file may have data appended to it.
        // This is outside the PE image size
        if (code_position < file_buffer.size()) {
            SectionHeader last_section = section_headers.back();
            auto code_start = last_section.PointerToRawData;
            auto code_size = last_section.SizeOfRawData;
            auto offset = code_start + code_size;
            file_input.seekp(0x000CD800);
            char *raw_data = file_buffer.data();
            file_input.write(&raw_data[0x000CD800], file_buffer.size() - 0x000CD800);
        }
    }
}
