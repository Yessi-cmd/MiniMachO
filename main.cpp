#include <iostream>
#include <vector>
#include <string>
#include <algorithm> // for sort
#include <sstream>   // for stringstream
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <arpa/inet.h>
#include <cctype>    // for isprint

#define ERROR_EXIT(msg) { std::cerr << "Error: " << msg << std::endl; return 1; }

// --- [Utils] 哈希算法 ---

// 1. 针对字符串的哈希 (遇 \0 结束)
uint64_t hash_djb2_string(const std::string& str) {
    uint64_t hash = 5381;
    for (char c : str) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }
    return hash;
}

// 2. 针对二进制数据的哈希 (需要指定长度，处理中间的 \0)
uint64_t hash_djb2_buffer(const uint8_t* buffer, size_t size) {
    uint64_t hash = 5381;
    for (size_t i = 0; i < size; i++) {
        hash = ((hash << 5) + hash) + buffer[i];
    }
    return hash;
}

// --- [Core] Mach-O 解析逻辑 ---

uint32_t get_best_slice_offset(void* map_addr, size_t size) {
    uint32_t magic = *(uint32_t*) map_addr;

    if (magic == FAT_CIGAM || magic == FAT_MAGIC) {
        struct fat_header* fh = (struct fat_header*)map_addr;
        uint32_t nfat_arch = ntohl(fh->nfat_arch);
        struct fat_arch* arch = (struct fat_arch*)((uint8_t*)map_addr + sizeof(struct fat_header));

        for (uint32_t i = 0; i < nfat_arch; i++) {
            cpu_type_t cputype = ntohl(arch->cputype);
            uint32_t offset = ntohl(arch->offset);
            if (cputype == CPU_TYPE_ARM64) return offset;
            arch++;
        }
        return 0;
    }
    return 0;
}

int main(int argc, char* argv[]) {
    // 1. 参数校验与文件映射
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <path_to_macho_file>" << std::endl;
        return 1;
    }

    const char* filepath = argv[1];
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) ERROR_EXIT("Failed to open file");

    struct stat st;
    if (fstat(fd, &st) < 0) ERROR_EXIT("Failed to get file stat");

    void* map_addr = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map_addr == MAP_FAILED) ERROR_EXIT("mmap failed");

    // 2. 定位切片
    uint32_t slice_offset = get_best_slice_offset(map_addr, st.st_size);
    struct mach_header_64* header = (struct mach_header_64*)((uint8_t*)map_addr + slice_offset);

    if (header->magic != MH_MAGIC_64) {
        std::cerr << "[-] Error: Not a valid 64-bit Mach-O." << std::endl;
        munmap(map_addr, st.st_size);
        close(fd);
        return 1;
    }

    std::cout << "[*] Parsing Target: " << filepath << std::endl;

    // --- 数据采集容器 (Data Collection) ---
    std::vector<std::string> feature_dylibs;     // 存储导入库名
    std::vector<uint8_t>     feature_opcodes;    // 存储 __text 代码段
    std::vector<std::string> feature_strings;    // 存储 __cstring 字符串

    // 3. 遍历 Load Commands
    uint8_t* cmd_ptr = (uint8_t*)header + sizeof(struct mach_header_64);

    for (uint32_t i = 0; i < header->ncmds; i++) {
        struct load_command* lc = (struct load_command*)cmd_ptr;

        // [特征1] 收集动态库依赖
        if (lc->cmd == LC_LOAD_DYLIB) {
            struct dylib_command* dylib_cmd = (struct dylib_command*)lc;
            uint32_t name_offset = dylib_cmd->dylib.name.offset;
            char* dylib_name = (char*)((uint8_t*)dylib_cmd + name_offset);
            feature_dylibs.push_back(std::string(dylib_name));
        }

        // [特征2 & 3] 收集代码段与字符串段
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64* seg = (struct segment_command_64*)lc;
            
            // 只有当段名为 __TEXT 时才深入解析 Section
            if (strncmp(seg->segname, "__TEXT", 6) == 0) {
                struct section_64* sec = (struct section_64*)((uint8_t*)seg + sizeof(struct segment_command_64));

                for (uint32_t j = 0; j < seg->nsects; j++) {
                    // A. 提取机器码 (__text)
                    if (strncmp(sec->sectname, "__text", 6) == 0) {
                        uint8_t* code_ptr = (uint8_t*)header + sec->offset;
                        // 将原始字节存入 vector
                        if (sec->size > 0) {
                            feature_opcodes.insert(feature_opcodes.end(), code_ptr, code_ptr + sec->size);
                        }
                    }

                    // B. 提取字符串 (__cstring)
                    if (strncmp(sec->sectname, "__cstring", 16) == 0) {
                        uint8_t* str_ptr = (uint8_t*)header + sec->offset;
                        uint64_t size = sec->size;
                        std::string temp_buffer;

                        for (uint64_t k = 0; k < size; k++) {
                            char c = (char)str_ptr[k];
                            if (isprint(c)) {
                                temp_buffer += c;
                            } else {
                                // 过滤逻辑：只有长度 > 4 才算有效特征
                                if (temp_buffer.length() > 4) {
                                    feature_strings.push_back(temp_buffer);
                                }
                                temp_buffer.clear();
                            }
                        }
                    }
                    sec++; // 下一个 section
                }
            }
        }
        cmd_ptr += lc->cmdsize;
    }

    // --- 4. 向量化计算与指纹生成 (Vectorization & Hashing) ---

    // [计算特征 1] 依赖哈希 (Import Hash)
    // 逻辑：排序 -> 拼接 -> 哈希
    std::sort(feature_dylibs.begin(), feature_dylibs.end());
    std::string dylib_blob;
    for (const auto& name : feature_dylibs) {
        dylib_blob += name + "|";
    }
    uint64_t hash_imphash = hash_djb2_string(dylib_blob);

    // [计算特征 2] 代码哈希 (Code Hash)
    // 逻辑：直接对二进制流计算哈希
    // 注意：如果文件巨大，这里可以只取前 4KB (4096 bytes)
    uint64_t hash_code = 0;
    if (!feature_opcodes.empty()) {
        hash_code = hash_djb2_buffer(feature_opcodes.data(), feature_opcodes.size());
    }

    // [计算特征 3] 数据哈希 (String Hash)
    // 逻辑：拼接所有提取到的字符串 -> 哈希
    std::string string_blob;
    for (const auto& s : feature_strings) {
        string_blob += s + "|";
    }
    uint64_t hash_string_data = hash_djb2_string(string_blob);

    // --- 5. 最终报告输出 (Report) ---
    std::cout << "\n========== MiniMachO Analysis Report ==========" << std::endl;
    std::cout << "[INFO] Imports Found: " << feature_dylibs.size() << std::endl;
    std::cout << "[INFO] Code Size:     " << feature_opcodes.size() << " bytes" << std::endl;
    std::cout << "[INFO] Strings Found: " << feature_strings.size() << std::endl;
    std::cout << "-----------------------------------------------" << std::endl;
    // 使用 hex 输出，方便查看
    std::cout << "1. Import Hash: 0x" << std::hex << hash_imphash << std::endl;
    std::cout << "2. Code Hash:   0x" << std::hex << hash_code << std::endl;
    std::cout << "3. String Hash: 0x" << std::hex << hash_string_data << std::endl;
    std::cout << "===============================================" << std::endl;

    munmap(map_addr, st.st_size);
    close(fd);
    return 0;
}