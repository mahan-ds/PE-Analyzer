#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <unordered_set>
#include <regex>

// Extract URLs from binary data
std::vector<std::string> extractURLs(const std::vector<char>& data) {
    std::vector<std::string> urls;
    std::string content(data.begin(), data.end());

    std::regex urlRegex(R"((https?|ftp):\/\/[^\s\"\'<>]+)");
    std::smatch match;

    auto it = content.cbegin();
    while (std::regex_search(it, content.cend(), match, urlRegex)) {
        urls.push_back(match[0]);
        it = match.suffix().first;
    }

    return urls;
}

// Convert RVA to File Offset in PE files
DWORD rvaToOffset(DWORD rva, IMAGE_NT_HEADERS* ntHeaders, BYTE* base) {
    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++section) {
        DWORD sectionStartRVA = section->VirtualAddress;
        DWORD sectionEndRVA = sectionStartRVA + section->Misc.VirtualSize;
        if (rva >= sectionStartRVA && rva < sectionEndRVA) {
            DWORD delta = rva - sectionStartRVA;
            return section->PointerToRawData + delta;
        }
    }
    return 0;
}

// Extract list of imported functions from a PE file
std::unordered_set<std::string> getImportedFunctions(const std::string& filePath) {

    std::unordered_set<std::string> imported;

    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        std::cerr << "Cannot open file: " << filePath << "\n";
        return imported;
    }

    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0);
    std::vector<char> buffer(fileSize);
    file.read(buffer.data(), fileSize);
    file.close();

    auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(buffer.data());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "Not a valid DOS/PE file.\n";
        return imported;
    }

    auto ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(buffer.data() + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "Not a valid NT header.\n";
        return imported;
    }

    IMAGE_DATA_DIRECTORY importDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress == 0 || importDir.Size == 0) {
        std::cerr << "No import table.\n";
        return imported;
    }

    DWORD importOffset = rvaToOffset(importDir.VirtualAddress, ntHeaders, reinterpret_cast<BYTE*>(buffer.data()));
    auto importDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(buffer.data() + importOffset);

    while (importDesc->Name) {
        DWORD thunkOffset = rvaToOffset(importDesc->OriginalFirstThunk, ntHeaders, reinterpret_cast<BYTE*>(buffer.data()));
        auto thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(buffer.data() + thunkOffset);
        while (thunk && thunk->u1.AddressOfData) {
            DWORD nameOffset = rvaToOffset(thunk->u1.AddressOfData, ntHeaders, reinterpret_cast<BYTE*>(buffer.data()));
            auto importByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(buffer.data() + nameOffset);
            imported.insert(std::string(reinterpret_cast<char*>(importByName->Name)));
            ++thunk;
        }
        ++importDesc;
    }

    return imported;
}

void printUsage() {
    std::cout << "Usage:\n"
              << "  pe_checker --file <path_to_exe_or_dll> [-f <FunctionName> ...] [-U]\n";
}

int main(int argc, char* argv[]) {
    if (argc < 3 || std::string(argv[1]) != "--file") {
        printUsage();
        return 1;
    }

    std::string filePath = argv[2];
    std::vector<std::string> functions;
    bool extractUrls = false;

    // پردازش آرگومان‌ها
    for (int i = 3; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-f" && i + 1 < argc) {
            functions.push_back(argv[++i]);
        } else if (arg == "-U") {
            extractUrls = true;
        }
    }

    // Check if specific functions are imported
    if (!functions.empty()) {
        auto imported = getImportedFunctions(filePath);
        for (const auto& func : functions) {
            if (imported.find(func) != imported.end()) {
                std::cout << func << ": found\n";
            } else {
                std::cout << func << ": not found\n";
            }
        }
    }

    // extract URLs
    if (extractUrls) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file) {
            std::cerr << "Cannot open file: " << filePath << "\n";
            return 1;
        }

        file.seekg(0, std::ios::end);
        size_t fileSize = file.tellg();
        file.seekg(0);
        std::vector<char> buffer(fileSize);
        file.read(buffer.data(), fileSize);
        file.close();

        auto urls = extractURLs(buffer);
        if (urls.empty()) {
            std::cout << "No URLs found in binary.\n";
        } else {
            std::cout << "URLs found:\n";
            for (const auto& url : urls) {
                std::cout << "  " << url << "\n";
            }
        }
    }

    return 0;
}
