#include "module.h"

#include <istream>

#define WIN64_DEF


using Byte = unsigned char;
using Word = unsigned short;
using DWord = unsigned long;
using Long = long;
using ULongLong = unsigned long long;


// DOS .EXE header
struct ImageDosHeader
{
    Word e_magic;    // Magic number
    Word e_cblp;     // Bytes on last page of file
    Word e_cp;       // Pages in file
    Word e_crlc;     // Relocations
    Word e_cparhdr;  // Size of header in paragraphs
    Word e_minalloc; // Minimum extra paragraphs needed
    Word e_maxalloc; // Maximum extra paragraphs needed
    Word e_ss;       // Initial (relative) SS value
    Word e_sp;       // Initial SP value
    Word e_csum;     // Checksum
    Word e_ip;       // Initial IP value
    Word e_cs;       // Initial (relative) CS value
    Word e_lfarlc;   // File address of relocation table
    Word e_ovno;     // Overlay number
    Word e_res[4];   // Reserved words
    Word e_oemid;    // OEM identifier (for e_oeminfo)
    Word e_oeminfo;  // OEM information; e_oemid specific
    Word e_res2[10]; // Reserved words
    Long e_lfanew;   // File address of new exe header
};


std::istream & operator>>(std::istream & is, ImageDosHeader & val)
{
    is.read(reinterpret_cast<char *>(&val), sizeof(val));
    return is;
}


constexpr Word MagicAsNumber(const char(&s)[3])
{
    return (s[0]) | (s[1] << 8);
};


struct ImageNtHeaders
{
    DWord Signature;

    struct ImageFileHeader
    {
        Word  Machine;
        Word  NumberOfSections;
        DWord TimeDateStamp;
        DWord PointerToSymbolTable;
        DWord NumberOfSymbols;
        Word  SizeOfOptionalHeader;
        Word  Characteristics;
    } FileHeader;

    struct ImageOptionalHeader
    {
        // Standard fields.

        Word  Magic;
        Byte  MajorLinkerVersion;
        Byte  MinorLinkerVersion;
        DWord SizeOfCode;
        DWord SizeOfInitializedData;
        DWord SizeOfUninitializedData;
        DWord AddressOfEntryPoint;
        DWord BaseOfCode;

#ifndef WIN64_DEF
        DWord   BaseOfData;
#endif

        using Special =
#ifdef WIN64_DEF
            ULongLong
#else
            DWord
#endif
            ;

        // NT additional fields.

        Special ImageBase;
        DWord   SectionAlignment;
        DWord   FileAlignment;
        Word    MajorOperatingSystemVersion;
        Word    MinorOperatingSystemVersion;
        Word    MajorImageVersion;
        Word    MinorImageVersion;
        Word    MajorSubsystemVersion;
        Word    MinorSubsystemVersion;
        DWord   Win32VersionValue;
        DWord   SizeOfImage;
        DWord   SizeOfHeaders;
        DWord   CheckSum;
        Word    Subsystem;
        Word    DllCharacteristics;
        Special SizeOfStackReserve;
        Special SizeOfStackCommit;
        Special SizeOfHeapReserve;
        Special SizeOfHeapCommit;
        DWord   LoaderFlags;
        DWord   NumberOfRvaAndSizes;

        static constexpr int IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;

        struct ImageDataDirectory
        {
            DWord VirtualAddress;
            DWord Size;
        } DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];

    } OptionalHeader;
};


std::istream & operator>>(std::istream & is, ImageNtHeaders & val)
{
    is.read(reinterpret_cast<char *>(&val), sizeof(val));
    return is;
}


struct ImageExportDirectory
{
    DWord Characteristics;
    DWord TimeDateStamp;
    Word  MajorVersion;
    Word  MinorVersion;
    DWord Name;
    DWord Base;
    DWord NumberOfFunctions;
    DWord NumberOfNames;
    DWord AddressOfFunctions;    // RVA from base of image
    DWord AddressOfNames;        // RVA from base of image
    DWord AddressOfNameOrdinals; // RVA from base of image
};


std::istream & operator>>(std::istream & is, ImageExportDirectory & val)
{
    is.read(reinterpret_cast<char *>(&val), sizeof(val));
    return is;
}


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
