// test.cpp
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <dirent.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <iomanip>
#include <algorithm>
#include <cstring> // for strerror

#include "comm.h"

// --- 辅助函数：Hex 转 Bytes ---
std::vector<unsigned char> hex_string_to_bytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    std::string clean_hex;
    for (char c : hex) if (c != ' ') clean_hex += c;
    for (size_t i = 0; i < clean_hex.length(); i += 2) {
        std::string byteString = clean_hex.substr(i, 2);
        char byte = (char)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

class ShamiTool {
private:
    int fd;
public:
    ShamiTool() {
        fd = open("/dev/shami", O_RDWR);
        if (fd < 0) {
            perror("[-] 驱动打开失败");
            exit(-1);
        }
    }
    ~ShamiTool() { if (fd > 0) close(fd); }

    int get_pid_by_name(const std::string& package_name) {
        DIR* dir = opendir("/proc");
        if (!dir) return -1;
        struct dirent* ptr;
        while ((ptr = readdir(dir)) != nullptr) {
            if (ptr->d_type != DT_DIR) continue;
            int pid = atoi(ptr->d_name);
            if (pid <= 0) continue;
            std::ifstream cmdline("/proc/" + std::to_string(pid) + "/cmdline");
            std::string line;
            if (std::getline(cmdline, line)) {
                if (line.find(package_name) != std::string::npos) {
                    closedir(dir);
                    return pid;
                }
            }
        }
        closedir(dir);
        return -1;
    }

    void search_maps(int pid, const std::string& keyword) {
        std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
        std::string line;
        bool found = false;
        std::cout << "\n[Maps 搜索结果: " << keyword << "]" << std::endl;
        
        while (std::getline(maps, line)) {
            if (keyword.empty() || line.find(keyword) != std::string::npos) {
                std::cout << line << std::endl;
                found = true;
            }
        }
        if (!found) std::cout << "[-] 未找到相关内存段" << std::endl;
    }

    std::pair<uintptr_t, size_t> get_module_range(int pid, const std::string& module_name) {
        std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
        std::string line;
        uintptr_t min_addr = -1;
        uintptr_t max_addr = 0;
        bool found = false;

        while (std::getline(maps, line)) {
            if (line.find(module_name) != std::string::npos) {
                found = true;
                size_t dash_pos = line.find('-');
                size_t space_pos = line.find(' ');
                try {
                    uintptr_t start = std::stoull(line.substr(0, dash_pos), nullptr, 16);
                    uintptr_t end = std::stoull(line.substr(dash_pos + 1, space_pos - dash_pos - 1), nullptr, 16);
                    if (start < min_addr) min_addr = start;
                    if (end > max_addr) max_addr = end;
                } catch (...) { continue; }
            }
        }
        if (!found) return {0, 0};
        return {min_addr, max_addr - min_addr};
    }

    bool read_mem(int pid, uintptr_t addr, void* buffer, size_t size) {
        COPY_MEMORY cm = {pid, addr, buffer, size};
        return ioctl(fd, OP_READ_MEM, &cm) == 0;
    }

    bool write_mem(int pid, uintptr_t addr, void* buffer, size_t size) {
        COPY_MEMORY cm = {pid, addr, buffer, size};
        return ioctl(fd, OP_WRITE_MEM, &cm) == 0;
    }

    // --- 新增：添加 Uprobe ---
    bool add_uprobe(int pid, uintptr_t addr) {
        UPROBE_CONFIG uc = {pid, addr};
        if (ioctl(fd, OP_ADD_UPROBE, &uc) == 0) {
            std::cout << "[+] Uprobe 设置成功! 请查看 dmesg 日志。" << std::endl;
            return true;
        } else {
            perror("[-] Uprobe 设置失败");
            return false;
        }
    }

    // --- 新增：移除 Uprobe ---
    bool del_uprobe(int pid, uintptr_t addr) {
        UPROBE_CONFIG uc = {pid, addr};
        if (ioctl(fd, OP_DEL_UPROBE, &uc) == 0) {
            std::cout << "[+] Uprobe 移除成功。" << std::endl;
            return true;
        } else {
            perror("[-] Uprobe 移除失败");
            return false;
        }
    }
};

void perform_dump(ShamiTool& tool, int pid, uintptr_t start_addr, size_t len, std::string filename) {
    std::ofstream outfile(filename, std::ios::binary);
    if (!outfile.is_open()) return;

    size_t chunk_size = 4096;
    std::vector<char> buffer(chunk_size);
    size_t total_read = 0;
    
    std::cout << "[*] Dumping: 0x" << std::hex << start_addr << " (" << std::dec << len << " bytes)" << std::endl;

    while (total_read < len) {
        size_t current_read = std::min(chunk_size, len - total_read);
        uintptr_t current_addr = start_addr + total_read;
        if (tool.read_mem(pid, current_addr, buffer.data(), current_read)) {
            outfile.write(buffer.data(), current_read);
        } else {
            std::vector<char> zeros(current_read, 0);
            outfile.write(zeros.data(), current_read);
        }
        total_read += current_read;
        if (len > 1024*1024) {
            int progress = (int)((total_read * 100) / len);
            if (progress % 10 == 0) std::cout << "\r进度: " << progress << "%" << std::flush;
        }
    }
    outfile.close();
    std::cout << "\n[+] 完成: " << filename << std::endl;
}

void show_menu() {
    std::cout << "\n========= Shami Pro (ARM64) =========" << std::endl;
    std::cout << "1. 获取进程 PID" << std::endl;
    std::cout << "2. 搜索 Maps" << std::endl;
    std::cout << "3. 读取内存 (HEX)" << std::endl;
    std::cout << "4. 写入内存 (HEX)" << std::endl;
    std::cout << "5. Dump 内存" << std::endl;
    std::cout << "6. [+] 设置 Uprobe 断点 (Monitor)" << std::endl;
    std::cout << "7. [-] 移除 Uprobe 断点" << std::endl;
    std::cout << "0. 退出" << std::endl;
    std::cout << "--------------------------------------" << std::endl;
    std::cout << "请选择: ";
}

int main() {
    ShamiTool tool;
    int pid = -1;
    int choice;
    std::string input_str;

    while (true) {
        show_menu();
        std::cin >> choice;
        if (std::cin.fail()) { std::cin.clear(); std::cin.ignore(); continue; }
        if (choice == 0) break;

        switch (choice) {
            case 1: {
                std::cout << "输入包名: "; std::cin >> input_str;
                pid = tool.get_pid_by_name(input_str);
                std::cout << (pid != -1 ? "[+] PID: " + std::to_string(pid) : "[-] 未找到") << std::endl;
                break;
            }
            case 2: {
                if (pid == -1) break;
                std::cout << "关键字: "; std::cin.ignore(); std::getline(std::cin, input_str);
                tool.search_maps(pid, input_str);
                break;
            }
            case 3: { // Read
                if (pid == -1) break;
                uintptr_t addr; size_t len;
                std::cout << "地址(HEX): "; std::cin >> std::hex >> addr;
                std::cout << "长度(DEC): "; std::cin >> std::dec >> len;
                std::vector<unsigned char> buf(len);
                if (tool.read_mem(pid, addr, buf.data(), len)) {
                    std::cout << "DATA: ";
                    for(auto b : buf) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b << " ";
                    std::cout << std::dec << std::endl;
                }
                break;
            }
            case 4: { // Write
                if (pid == -1) break;
                uintptr_t addr; 
                std::cout << "地址(HEX): "; std::cin >> std::hex >> addr;
                std::cout << "HEX数据: "; std::cin.ignore(); std::getline(std::cin, input_str);
                auto bytes = hex_string_to_bytes(input_str);
                tool.write_mem(pid, addr, bytes.data(), bytes.size());
                break;
            }
            case 5: { // Dump
                if (pid == -1) break;
                std::cout << "模块名 (如 lib.so): "; std::cin >> input_str;
                auto range = tool.get_module_range(pid, input_str);
                if (range.second > 0) perform_dump(tool, pid, range.first, range.second, input_str + ".dump");
                else std::cout << "[-] 模块未找到" << std::endl;
                break;
            }
            case 6: { // Add Uprobe
                if (pid == -1) { std::cout << "[-] 请先获取 PID" << std::endl; break; }
                uintptr_t addr;
                std::cout << "输入绝对虚拟地址 (HEX) [配合 maps 查看]: "; 
                std::cin >> std::hex >> addr;
                tool.add_uprobe(pid, addr);
                break;
            }
            case 7: { // Del Uprobe
                if (pid == -1) { std::cout << "[-] 请先获取 PID" << std::endl; break; }
                uintptr_t addr;
                std::cout << "输入已下断点的地址 (HEX): "; 
                std::cin >> std::hex >> addr;
                tool.del_uprobe(pid, addr);
                break;
            }
        }
    }
    return 0;
}
