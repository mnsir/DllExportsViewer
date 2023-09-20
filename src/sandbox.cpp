#include <fstream>
#include <iostream>

#include "module.h"


int main()
{
    std::fstream is("C:/Windows/System32/user32.dll", std::ios::in | std::ios::binary);
    auto && names = ReadDllExports(is);
    for (auto && s : names)
        std::cout << s << '\n';
}