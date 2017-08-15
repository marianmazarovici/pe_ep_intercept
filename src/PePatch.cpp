#include "PePatch.hpp"
#include <keystone/keystone.h>
#include <cinttypes>
#include <iostream>
#include <string>
#include <vector>
#include <memory>

static const uint32_t SECTION_MAX_NAME_SIZE = IMAGE_SIZEOF_SHORT_NAME;

static const uint32_t SECTION_CHARACTERISTICS =
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ |
        IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

static uint32_t Align(uint32_t num, uint32_t multiple) {
    return ((num + multiple - 1) / multiple) * multiple;
}

static bool ReplaceDword(std::vector<char> code_buffer, uint32_t target_dword, uint32_t replace_dword) {
    for (size_t i = 0; i < code_buffer.size(); i++) {
        // First byte
        if (code_buffer[i] != (target_dword & 0xff)) {
            continue;
        }

        size_t j = 1;

        while (j < 4) {
            // Rest of bytes
            if (code_buffer[i + j] == (target_dword >> ((8 * j) & 0xff))) {
                j++;
            } else {
                // Failed to match all bytes
                break;
            }
        }

        if (j == 4) {
            for (size_t re_i = 0; re_i < j; re_i++) {
                uint32_t num = (replace_dword >> (8 * re_i)) & 0xff;
                auto replace_byte = static_cast<char>(num);
                code_buffer[i + re_i] = replace_byte;
            }

            return true;
        }
    }

    return false;
}

static std::vector<char> CopyBytes(char *byte_start, char *byte_end) {
    if (byte_start >= byte_end) {
        throw std::runtime_error("pointer is greater or equal than ending pointer");
    }

    std::vector<char> subroutine_buffer(byte_start, byte_end);
    return subroutine_buffer;
}


namespace PeEpIntercept {
    PePatch::PePatch(std::string path) : path(path) {
        file_input.exceptions(std::ifstream::failbit | std::ifstream::badbit);
        file_input.open(path, std::ios::binary |
                              std::ifstream::ate |
                              std::fstream::in |
                              std::fstream::out);
        std::streamsize size = file_input.tellg();
        file_input.seekg(0, std::ios::beg);

        if (size <= 0) {
            throw std::runtime_error("could not get file size");
        }

        std::vector<char> file_buffer((uint32_t) size);

        if (!file_input.read(file_buffer.data(), size)) {
            throw std::runtime_error("could not read file");
        }

        const auto *raw_buffer = file_buffer.data();

        // Portable Executable headers
        dos_header = *(PIMAGE_DOS_HEADER) raw_buffer;

        if (dos_header.e_magic != 0x5a4d) {
            throw std::runtime_error("could not executable read headers");
        }

        size_t machine_offset = dos_header.e_lfanew + sizeof(uint32_t);
        auto machine = static_cast<uint16_t>((raw_buffer[machine_offset + 1] << 8) + raw_buffer[machine_offset]);

        switch (machine) {
            case 0x014c:
                type = PeArch::x86;
                break;
            case 0x8664:
                type = PeArch::x64;
                break;
            default:
                throw std::runtime_error("executable type is not x86 or x64");
        }

        uint32_t first_section = 0;

        if (type == PeArch::x86) {
            auto nt_header = (PIMAGE_NT_HEADERS32) &raw_buffer[dos_header.e_lfanew];
            file_header = *(PIMAGE_FILE_HEADER) &nt_header->FileHeader;
            first_section = dos_header.e_lfanew + sizeof(IMAGE_NT_HEADERS32);
            nt_header_signature = nt_header->Signature;
            //optional_header = *(PIMAGE_OPTIONAL_HEADER32) &nt_header->OptionalHeader;
        } else if (type == PeArch::x64) {
            auto nt_header = (PIMAGE_NT_HEADERS64) &raw_buffer[dos_header.e_lfanew];
            file_header = *(PIMAGE_FILE_HEADER) &nt_header->FileHeader;
            first_section = dos_header.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
            nt_header_signature = nt_header->Signature;
            optional_header = *(PIMAGE_OPTIONAL_HEADER64) &nt_header->OptionalHeader;
        }

        if (nt_header_signature != 0x4550) {
            throw std::runtime_error("This is not a portable executable");
        }

        original_entry_point = optional_header.AddressOfEntryPoint;

        for (uint32_t i = 0; i < file_header.NumberOfSections; i++) {
            uint32_t section_index = i * sizeof(IMAGE_SECTION_HEADER);
            uint32_t next_section = first_section + section_index;
            auto hdr = *(PIMAGE_SECTION_HEADER) &raw_buffer[next_section];
            section_headers.push_back(hdr);
        }

        auto rest_of_data = first_section;
        auto count = static_cast<uint32_t>(section_headers.size());
        rest_of_data += count * sizeof(IMAGE_SECTION_HEADER);

        // Excludes headers since we already have the initialised structs
        auto data_start = file_buffer.begin() + rest_of_data;
        this->file_buffer.assign(data_start, file_buffer.end());
    }

    std::vector<char> PePatch::Assemble(const std::string &assembly) {
        std::vector<char> instructions;

        if (assembly.empty()) {
            return instructions;
        }

        unsigned char *encode = nullptr;
        ks_engine *ks = nullptr;
        size_t count;
        size_t size;

        auto code_deleter = [](unsigned char *code_ptr) {
            ks_free(code_ptr);
        };

        auto ks_deleter = [](ks_engine *ks_ptr) {
            ks_close(ks_ptr);
        };

        ks_mode instruct_mode;

        switch (type) {
            case PeArch::x86:
                instruct_mode = KS_MODE_32;
                break;
            case PeArch::x64:
                instruct_mode = KS_MODE_64;
                break;
            default:
                throw std::runtime_error("executable type not supported");
        }

        if (ks_open(KS_ARCH_X86, instruct_mode, &ks) != KS_ERR_OK) {
            throw std::runtime_error("failed to open keystone");
        }

        std::unique_ptr<ks_engine[],
                decltype(ks_deleter)> ks_ptr(ks, ks_deleter);

        if (ks_asm(ks, assembly.c_str(), 0, &encode, &size, &count) != KS_ERR_OK) {
            throw std::runtime_error("failed to assemble instructions");
        }

        std::unique_ptr<unsigned char[],
                decltype(code_deleter)> encode_ptr(encode, code_deleter);

        if (size > 0xffffffff) {
            throw std::runtime_error("exceeded max section size");
        }

        for (size_t i = 0; i < size; i++) {
            auto encoded = static_cast<char>(encode[i]);
            instructions.push_back(encoded);
        }

        return instructions;
    }

    bool PePatch::HasSection(const std::string &section_name) {
        for (auto &section : section_headers) {
            if (reinterpret_cast<char *>(section.Name) == section_name) {
                return true;
            }
        }

        return false;
    }

    void PePatch::AddSection(const std::string &name, uint32_t code_size) {
        auto last_section = section_headers.back();
        auto aligned_size = Align(code_size, optional_header.FileAlignment);
        IMAGE_SECTION_HEADER new_section{};

        new_section.Characteristics = SECTION_CHARACTERISTICS;
        new_section.SizeOfRawData = aligned_size;
        new_section.Misc.VirtualSize = Align(
                aligned_size,
                optional_header.SectionAlignment);
        new_section.PointerToRawData = Align(
                last_section.SizeOfRawData + last_section.PointerToRawData,
                optional_header.FileAlignment);
        new_section.VirtualAddress = Align(
                last_section.Misc.VirtualSize + last_section.VirtualAddress,
                optional_header.SectionAlignment);

        for (size_t i = 0; i < SECTION_MAX_NAME_SIZE; i++) {
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
        section_headers.push_back(new_section);
    }

    void PePatch::SaveFile(std::string new_path, std::vector<char> code_buffer) {
        char dos_bytes[sizeof(dos_header)];
        memcpy(dos_bytes, &dos_header, sizeof(dos_header));
        file_input.seekg(0);
        file_input.write(dos_bytes, sizeof(dos_header));

        IMAGE_NT_HEADERS nt_headers{
                nt_header_signature,
                file_header,
                optional_header};

        char nt_bytes[sizeof(nt_headers)];
        memcpy(nt_bytes, &nt_headers, sizeof(nt_headers));
        file_input.seekg(dos_header.e_lfanew, std::ios_base::beg);
        file_input.write(nt_bytes, sizeof(nt_headers));
        uint32_t address = dos_header.e_lfanew + sizeof(nt_headers);

        for (auto &section_header : section_headers) {
            char hdr_bytes[sizeof(section_header)];
            memcpy(hdr_bytes, &section_header, sizeof(section_header));
            file_input.seekg(address);
            file_input.write(hdr_bytes, sizeof(section_header));
            address += sizeof(section_header);
        }

        auto new_section = &section_headers.back();
        uint32_t code_position = new_section->PointerToRawData;
        file_input.seekg(code_position);

        // Padding might be required otherwise the loader will fail
        // when loading the executable
        while (code_buffer.size() < new_section->SizeOfRawData) {
            code_buffer.push_back(0);
        }

        file_input.write(code_buffer.data(), code_buffer.size());
    }

    uint32_t PePatch::GetOriginalEntryPoint() {
        return original_entry_point;
    }

    PeArch PePatch::GetPeArch() {
        return type;
    }
} // namespace PeEpIntercept