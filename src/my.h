#pragma once
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
