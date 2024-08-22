# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "/Users/jeremytubongbanua/esp/esp-idf/components/bootloader/subproject"
  "/Users/jeremytubongbanua/GitHub/at_c/examples/esp32/pkam_authenticate/build/bootloader"
  "/Users/jeremytubongbanua/GitHub/at_c/examples/esp32/pkam_authenticate/build/bootloader-prefix"
  "/Users/jeremytubongbanua/GitHub/at_c/examples/esp32/pkam_authenticate/build/bootloader-prefix/tmp"
  "/Users/jeremytubongbanua/GitHub/at_c/examples/esp32/pkam_authenticate/build/bootloader-prefix/src/bootloader-stamp"
  "/Users/jeremytubongbanua/GitHub/at_c/examples/esp32/pkam_authenticate/build/bootloader-prefix/src"
  "/Users/jeremytubongbanua/GitHub/at_c/examples/esp32/pkam_authenticate/build/bootloader-prefix/src/bootloader-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/Users/jeremytubongbanua/GitHub/at_c/examples/esp32/pkam_authenticate/build/bootloader-prefix/src/bootloader-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/Users/jeremytubongbanua/GitHub/at_c/examples/esp32/pkam_authenticate/build/bootloader-prefix/src/bootloader-stamp${cfgdir}") # cfgdir has leading slash
endif()
