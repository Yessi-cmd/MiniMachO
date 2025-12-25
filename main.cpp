#include <iostream>
#include <vector>
#include <algorithm>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <arpa/inet.h>

#define ERROR_EXIT(msg) { std::cerr << "Error: " << msg << std::endl; return 1; }

unsigned long hash_djb2(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    return hash;
}

/**
 * 【核心函数】获取适配当前 CPU 的 Mach-O 切片偏移量
 * * @param map_addr: mmap 映射的整个文件内存起始地址
 * @param size: 文件总大小
 * @return: 真正的 mach_header_64 开始的偏移量 (offset)。如果是单架构，返回 0。
 */

 uint32_t get_best_slice_offset(void* map_addr, size_t size){
    uint32_t magic = *(u_int32_t*) map_addr;

    //如果是fat
    if (magic == FAT_CIGAM || magic == FAT_MAGIC)
    {
        struct fat_header* fh = (struct fat_header*)map_addr;

        uint32_t nfat_arch = ntohl(fh->nfat_arch);
        std::cout << "Detected Fat Binary with " << nfat_arch << std::endl;

        struct fat_arch *arch = (struct fat_arch*)((u_int8_t*)map_addr + sizeof(struct fat_header));

        for(uint32_t i = 0; i < nfat_arch; i++)
        {
            cpu_type_t cputype = ntohl(arch->cputype);
            uint32_t offset = ntohl(arch->offset);
            if(cputype == CPU_TYPE_ARM64) return offset;
            arch++;
        }
        std::cerr << "Waring No ARM64 found in Fat Binary" << std::endl;
        return 0;
    }
    return 0;

 }

int main(int argc, char* argv[]) {
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

    uint32_t slice_offset = get_best_slice_offset(map_addr, st.st_size);

    // 1. 解析 Header
    struct mach_header_64* header = (struct mach_header_64*)((uint8_t*)map_addr + slice_offset);

    if(header->magic != MH_MAGIC_64)
    {
        std::cerr << "ERROR: Target slice is not valid 64-bit Mach-O" << std::endl;
        munmap(map_addr, st.st_size);
        close(fd);
        return 1;
    }

    

    std::cout << "[*] Parsing file: " << filepath << std::endl;
    std::cout << "[*] Total Commands: " << header->ncmds << std::endl;

    // 2. 【核心逻辑】指针跳过 Header，指向第一条 Load Command
    // 注意：必须转成 uint8_t* 才能按字节偏移，否则指针+1会跳过整个结构体大小
    uint8_t* cmd_ptr = (uint8_t*)header + sizeof(struct mach_header_64);

    std::vector<std::string> dylib_list;

    // 3. 循环遍历所有命令
    for (uint32_t i = 0; i < header->ncmds; i++) {
        // 把当前指针看作通用的 load_command 结构体，方便读取 cmd 和 cmdsize
        struct load_command* lc = (struct load_command*)cmd_ptr;

        
        if (lc->cmd == LC_LOAD_DYLIB) {
            // 强转为 dylib_command 结构体
            struct dylib_command* dylib_cmd = (struct dylib_command*)lc;

            // 获取字符串偏移量 (注意：这个 offset 是相对于 dylib_cmd 起始位置的)
            uint32_t name_offset = dylib_cmd->dylib.name.offset;

            // 计算字符串在内存中的真实地址
            char* dylib_name = (char*)((uint8_t*)dylib_cmd + name_offset);

            std::cout << "    [+] Found Import: " << dylib_name << std::endl;
            dylib_list.push_back(std::string(dylib_name));
        }
        
        if(lc->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 *seg = (struct segment_command_64*)lc;
            if(strncmp(seg->segname, "__TEXT", 6) == 0)
            {
                struct section_64 *sec = (struct section_64*)((uint8_t*)seg + sizeof(struct segment_command_64));

                for(uint32_t j = 0; j < seg->nsects; j++)
                {
                    if(strncmp(sec->sectname, "__text", 6) == 0)
                    {
                        std::cout << "    [!] Found Code Section (__text)" << std::endl;
                        std::cout << "        Offset: " << sec->offset << std::endl;
                        std::cout << "        Size:   " << sec->size << std::endl;
                        uint8_t* code_ptr = (uint8_t*)header + sec->offset;
                        std::cout << "        Opcode Header: ";
                        for (int k = 0; k < 16 && k < sec->size; k++)
                        {
                            printf("%02x ", code_ptr[k]);
                        }
                        std::cout << "..." << std::endl;
                    }
                    sec++;
                }
            }
        }
        
        cmd_ptr += lc->cmdsize;
    }

    std::cout << "[*] Extraction Done. Found " << dylib_list.size() << " dylibs." << std::endl;
    // 这里如果要做哈希，就是对 dylib_list 进行排序 + 计算 Hash

    std::sort(dylib_list.begin(), dylib_list.end());
    // 6. 【核心算法】生成指纹
    // 逻辑：把所有 dylib 名字拼起来，中间加个分隔符，然后算哈希
    std::string combined_feature;
    for (const auto& name : dylib_list) {
        // 简单的数据清洗：去掉版本号或路径前缀在这里做 (面试可以说这点)
        // 这里演示最原始的：直接拼接
        combined_feature += name;
        combined_feature += "|"; // 分隔符，防止 "ab"+"c" 和 "a"+"bc" 混淆
    }

    if (combined_feature.empty()) {
        std::cout << "[-] No dylibs found. No feature generated." << std::endl;
    } else {
        unsigned long signature = hash_djb2(combined_feature.c_str());
        
        std::cout << "------------------------------------------------" << std::endl;
        std::cout << "[+] Final Behavioral Signature (Hash): " << std::hex << signature << std::endl;
        std::cout << "------------------------------------------------" << std::endl;
        std::cout << "Raw Feature String: " << combined_feature << std::endl; // 调试用，面试时展示给面试官看
    }




    munmap(map_addr, st.st_size);
    close(fd);
    return 0;
}