#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <arpa/inet.h>
#include <cctype>
#include <cmath>
#include <filesystem> // C++17 standard
#include <getopt.h>   // POSIX args

namespace fs = std::filesystem;

#define ERROR_EXIT(msg) { std::cerr << "[-] Error: " << msg << std::endl; return; }

// --- [Structs] Code Signing Structures (手动定义以实现零依赖) ---
// Reference: xnu/osfmk/kern/cs_blobs.h

#define CSMAGIC_EMBEDDED_SIGNATURE 0xfade0cc0
#define CSMAGIC_REQUIREMENT        0xfade0c00
#define CSMAGIC_CODEDIRECTORY      0xfade0c02

struct CS_BlobIndex {
    uint32_t type;   // type of entry
    uint32_t offset; // offset of entry
};

struct CS_SuperBlob {
    uint32_t magic;  // magic number
    uint32_t length; // total length of SuperBlob
    uint32_t count;  // number of index entries
    // followed by CS_BlobIndex index[];
};

// --- [Utils] 哈希算法 ---
uint64_t hash_djb2_string(const std::string& str) {
    uint64_t hash = 5381;
    for (char c : str) hash = ((hash << 5) + hash) + c;
    return hash;
}

uint64_t hash_djb2_buffer(const uint8_t* buffer, size_t size) {
    uint64_t hash = 5381;
    for (size_t i = 0; i < size; i++) hash = ((hash << 5) + hash) + buffer[i];
    return hash;
}

double calculate_entropy(const uint8_t* data, size_t size) {
    if (size == 0) return 0.0;
    uint64_t frequency[256] = {0};
    for (size_t i = 0; i < size; i++) frequency[data[i]]++;
    double entropy = 0.0;
    double total = (double)size;
    for (int i = 0; i < 256; i++) {
        if (frequency[i] > 0) {
            double p = frequency[i] / total;
            entropy -= p * std::log2(p);
        }
    }
    return entropy;
}

uint32_t get_best_slice_offset(void* map_addr) {
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
    }
    return 0;
}

// --- [Core] 单文件分析逻辑 ---
void analyze_file(const std::string& filepath) {
    int fd = open(filepath.c_str(), O_RDONLY);
    if (fd < 0) {
        std::cerr << "[-] Failed to open: " << filepath << std::endl;
        return;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return;
    }
    
    // 忽略过小文件或空文件
    if (static_cast<uint64_t>(st.st_size) < sizeof(struct mach_header_64)) {
        close(fd);
        return;
    }

    void* map_addr = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map_addr == MAP_FAILED) {
        close(fd);
        return;
    }

    uint32_t slice_offset = get_best_slice_offset(map_addr);
    struct mach_header_64* header = (struct mach_header_64*)((uint8_t*)map_addr + slice_offset);

    // 基础校验
    if (header->magic != MH_MAGIC_64) {
        // 静默非 Mach-O 文件，仅在递归时有用
        munmap(map_addr, st.st_size);
        close(fd);
        return;
    }

    // --- 特征容器 ---
    std::vector<std::string> feature_dylibs;
    std::vector<uint8_t>     feature_opcodes;
    std::vector<std::string> feature_strings;
    
    // 签名相关信息
    bool is_signed = false;
    uint32_t cs_offset = 0;
    uint32_t cs_size = 0;
    std::string cs_status = "Not Found";

    uint8_t* cmd_ptr = (uint8_t*)header + sizeof(struct mach_header_64);

    for (uint32_t i = 0; i < header->ncmds; i++) {
        struct load_command* lc = (struct load_command*)cmd_ptr;

        // 1. 动态库依赖
        if (lc->cmd == LC_LOAD_DYLIB) {
            struct dylib_command* dylib_cmd = (struct dylib_command*)lc;
            uint32_t name_offset = dylib_cmd->dylib.name.offset;
            // 边界检查
            if (name_offset < lc->cmdsize) {
                char* dylib_name = (char*)((uint8_t*)dylib_cmd + name_offset);
                feature_dylibs.push_back(std::string(dylib_name));
            }
        }

        // 2. 代码段 (V5.1 全量扫描策略)
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64* seg = (struct segment_command_64*)lc;
            if (strncmp(seg->segname, "__TEXT", 6) == 0) {
                struct section_64* sec = (struct section_64*)((uint8_t*)seg + sizeof(struct segment_command_64));
                for (uint32_t j = 0; j < seg->nsects; j++) {
                    uint8_t* sec_data_ptr = (uint8_t*)header + sec->offset;
                    // 只有当 section 在文件范围内才读取
                    if (sec->offset + sec->size <= static_cast<uint64_t>(st.st_size) && sec->size > 0) {
                        feature_opcodes.insert(feature_opcodes.end(), sec_data_ptr, sec_data_ptr + sec->size);
                    }
                    
                    // 字符串提取
                    if (strncmp(sec->sectname, "__cstring", 16) == 0) {
                        uint8_t* str_ptr = (uint8_t*)header + sec->offset;
                        uint64_t size = sec->size;
                        std::string temp_buffer;
                        for (uint64_t k = 0; k < size; k++) {
                            char c = (char)str_ptr[k];
                            if (isprint(c)) temp_buffer += c;
                            else {
                                if (temp_buffer.length() > 4) feature_strings.push_back(temp_buffer);
                                temp_buffer.clear();
                            }
                        }
                    }
                    sec++;
                }
            }
        }

        // 3. [NEW] 签名检测 (LC_CODE_SIGNATURE)
        if (lc->cmd == LC_CODE_SIGNATURE) {
            struct linkedit_data_command* cs_cmd = (struct linkedit_data_command*)lc;
            cs_offset = cs_cmd->dataoff;
            cs_size = cs_cmd->datasize;
            
            // 验证签名 Blob
            if (slice_offset + cs_offset < st.st_size) {
                // 指向 CS_SuperBlob
                CS_SuperBlob* sb = (CS_SuperBlob*)((uint8_t*)map_addr + slice_offset + cs_offset);
                // CodeSign Blob 也是大端序，需要 ntohl
                uint32_t magic = ntohl(sb->magic);
                
                if (magic == CSMAGIC_EMBEDDED_SIGNATURE) {
                    is_signed = true;
                    cs_status = "Valid (Embedded)";
                } else {
                    cs_status = "Invalid Magic";
                }
            }
        }

        cmd_ptr += lc->cmdsize;
    }

    // --- 计算特征 ---
    std::sort(feature_dylibs.begin(), feature_dylibs.end());
    std::string dylib_blob;
    for (const auto& name : feature_dylibs) dylib_blob += name + "|";
    uint64_t hash_imphash = hash_djb2_string(dylib_blob);

    uint64_t hash_code = 0;
    double code_entropy = 0.0;
    if (!feature_opcodes.empty()) {
        hash_code = hash_djb2_buffer(feature_opcodes.data(), feature_opcodes.size());
        code_entropy = calculate_entropy(feature_opcodes.data(), feature_opcodes.size());
    }

    std::string string_blob;
    for (const auto& s : feature_strings) string_blob += s + "|";
    uint64_t hash_string_data = hash_djb2_string(string_blob);

    // --- 输出报告 ---
    std::cout << "Target: " << filepath << std::endl;
    std::cout << "  > Arch:       ARM64" << std::endl;
    std::cout << "  > Code Size:  " << feature_opcodes.size() << " bytes" << std::endl;
    
    // 输出签名信息
    std::cout << "  > Signature:  " << cs_status << std::endl;
    if (is_signed) {
        std::cout << "    |_ Offset:  " << cs_offset << std::endl;
        std::cout << "    |_ Size:    " << cs_size << " bytes" << std::endl;
    }

    // 输出哈希
    std::cout << "  > Fingerprints:" << std::endl;
    std::cout << "    |_ ImpHash: 0x" << std::hex << hash_imphash << std::endl;
    std::cout << "    |_ CodHash: 0x" << std::hex << hash_code << std::endl;
    std::cout << "    |_ StrHash: 0x" << std::hex << hash_string_data << std::dec << std::endl;
    
    // 输出熵值
    std::cout << "  > Entropy:    " << code_entropy << " / 8.0 ";
    if (code_entropy > 7.2) {
        std::cout << "\033[1;31m[!] PACKED/ENCRYPTED\033[0m" << std::endl;
    } else {
        std::cout << "[OK]" << std::endl;
    }
    std::cout << "-----------------------------------------------" << std::endl;

    munmap(map_addr, st.st_size);
    close(fd);
}

// --- [Main] 参数解析与递归控制 ---
void print_usage(const char* prog_name) {
    std::cerr << "Usage: " << prog_name << " [options] <file_or_directory>" << std::endl;
    std::cerr << "Options:" << std::endl;
    std::cerr << "  -r, --recursive    Recursively scan directories" << std::endl;
    std::cerr << "  -h, --help         Show this help message" << std::endl;
}

int main(int argc, char* argv[]) {
    bool recursive = false;
    int opt;
    static struct option long_options[] = {
        {"recursive", no_argument, 0, 'r'},
        {"help",      no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "rh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'r': recursive = true; break;
            case 'h': print_usage(argv[0]); return 0;
            default:  print_usage(argv[0]); return 1;
        }
    }

    if (optind >= argc) {
        std::cerr << "[-] Error: No target specified." << std::endl;
        print_usage(argv[0]);
        return 1;
    }

    std::string target_path = argv[optind];

    if (!fs::exists(target_path)) {
        std::cerr << "[-] Error: Path does not exist: " << target_path << std::endl;
        return 1;
    }

    // 目录扫描逻辑
    if (fs::is_directory(target_path)) {
        if (!recursive) {
            std::cerr << "[-] Error: " << target_path << " is a directory. Use -r to scan recursively." << std::endl;
            return 1;
        }

        std::cout << "[*] Starting recursive scan on: " << target_path << std::endl;
        std::cout << "-----------------------------------------------" << std::endl;
        
        for (const auto& entry : fs::recursive_directory_iterator(target_path)) {
            // 跳过符号链接，避免死循环
            if (entry.is_regular_file() && !entry.is_symlink()) {
                // 简单的文件后缀过滤（可选，这里为了演示全扫）
                analyze_file(entry.path().string());
            }
        }
    } else {
        // 单文件扫描
        analyze_file(target_path);
    }

    return 0;
}