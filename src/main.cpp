#include <string>
#include <iostream>
#include <sstream>
#include <vector>

#include <emscripten/emscripten.h>
#include <emscripten/bind.h>

#include "module.h"


constexpr bool verbose = false;


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

#ifdef __cplusplus
}
#endif

