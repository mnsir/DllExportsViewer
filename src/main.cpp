#include <string>
#include <string_view>
#include <iostream>
#include <sstream>
#include <fstream>
#include <vector>
#include <emscripten/emscripten.h>

#include <emscripten/bind.h>

#include "my.h"


constexpr bool verbose = false;

int main(int argc, char ** argv)
{
}

struct Sentinel
{
    ~Sentinel()
    {
        std::cout << "=== PROGRAM DEAD ===" << std::endl;
    }
} s;

struct sectionHeader
{
    unsigned char Name[8];
    unsigned int VirtualSize;
    unsigned int VirtualAddress;
    unsigned int SizeOfRawData;
    unsigned int PointerToRawData;
    unsigned int PointerToRelocations;
    unsigned int PointerToLineNumbers;
    unsigned short NumberOfRelocations;
    unsigned short NumberOfLineNumbers;
    unsigned int Characteristics;
};


template<typename T>
auto from_stream(std::istream & is)
{
    constexpr static auto size = sizeof(T);
    static union
    {
        T value;
        char bytes[size];
    } data;
    is.read(data.bytes, size);
    return data.value;
}


std::vector<std::string> ReadDllExports(std::istream & is)
{
    std::vector<std::string> res;
    
    ImageDosHeader idh;
    is >> idh;

    constexpr auto kImageDosSignature = MagicAsNumber("MZ");
    
    if (idh.e_magic == kImageDosSignature)
    {
        is.seekg(idh.e_lfanew, std::ios::beg);
        
        ImageNtHeaders inh;
        is >> inh;

        constexpr DWord kImageNumberOfDirectoryEntries = 16;
        
        if (inh.OptionalHeader.NumberOfRvaAndSizes == kImageNumberOfDirectoryEntries)
        {
            const auto ExportVirtualAddress = inh.OptionalHeader.DataDirectory[0].VirtualAddress;
            const auto ExportSize = inh.OptionalHeader.DataDirectory[0].Size;

            if (ExportVirtualAddress > 0 && ExportSize > 0)
            {
                const auto NumberOfSections = inh.FileHeader.NumberOfSections;
                if (inh.FileHeader.NumberOfSections > 0)
                {
                    std::vector<sectionHeader> sections;
                    sections.reserve(NumberOfSections);
                    for (int i = 0; i < NumberOfSections; i++)
                    {
                        sectionHeader item;
                        is.read(reinterpret_cast<char *>(item.Name), 8);
                        is.read(reinterpret_cast<char *>(&item.VirtualSize), 4);
                        is.read(reinterpret_cast<char *>(&item.VirtualAddress), 4);
                        is.read(reinterpret_cast<char *>(&item.SizeOfRawData), 4);
                        is.read(reinterpret_cast<char *>(&item.PointerToRawData), 4);
                        is.read(reinterpret_cast<char *>(&item.PointerToRelocations), 4);
                        is.read(reinterpret_cast<char *>(&item.PointerToLineNumbers), 4);
                        is.read(reinterpret_cast<char *>(&item.NumberOfRelocations), 2);
                        is.read(reinterpret_cast<char *>(&item.NumberOfLineNumbers), 2);
                        is.read(reinterpret_cast<char *>(&item.Characteristics), 4);
                        sections.push_back(item);
                    }
                    auto Rva2Offset = [&sections](size_t rva) -> size_t
                    {
                        for (auto && section : sections)
                            if (section.VirtualAddress + section.SizeOfRawData >= rva)
                                return section.PointerToRawData + (rva + section.SizeOfRawData) - (section.VirtualAddress + section.SizeOfRawData);
                        return -1;
                    };
                    const int offset = Rva2Offset(ExportVirtualAddress);
                    is.seekg(offset, std::ios::beg);

                    ImageExportDirectory ied;
                    is >> ied;

                    const auto NumberOfNames = ied.NumberOfNames;
                    const auto AddressOfNames = ied.AddressOfNames;

                    const unsigned int namesOffset = Rva2Offset(AddressOfNames);
                    is.seekg(namesOffset, std::ios::beg);

                    res.reserve(NumberOfNames);
                    for (int i = 0; i < NumberOfNames; i++)
                    {
                        const auto y = from_stream<unsigned int>(is);
                        auto pos = is.tellg();

                        auto qwe = Rva2Offset(y);
                        is.seekg(qwe, std::ios::beg);

                        std::string str;
                        std::getline(is, str, '\0');
                        res.emplace_back(std::move(str));

                        is.seekg(pos, std::ios::beg);
                    }
                }
            }
        }
    }
    return res;
}


#ifdef __cplusplus
extern "C" {
#endif

    void EMSCRIPTEN_KEEPALIVE PrintDllExports(char * const ptr, size_t size)
    {
        emscripten_log(EM_LOG_CONSOLE, "Hello, console");
        //emscripten_log(EM_LOG_CONSOLE, "%d", str.size());

        if (verbose)
            std::cout << "C++ START\n";

        std::string str(ptr, size);
        std::istringstream is(str, std::ios::in | std::ios::binary);

        auto &&names = ReadDllExports(is);
        for (auto &&s : names)
            std::cout << s << '\n';

        if (verbose)
            std::cout << "C++ FINISH_" << std::endl;
    }

    //void EMSCRIPTEN_KEEPALIVE ShutDown()
    //{
    //    exit(0);
    //}

#ifdef __cplusplus
}
#endif


