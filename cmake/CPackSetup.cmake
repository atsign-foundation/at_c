# package info
set(CPACK_PACKAGE_NAME atsdk)
set(CPACK_PACKAGE_DESCRIPTION "Atsign's atSDK library")
set(CPACK_PACKAGE_VERSION 0.3.0)
set(CPACK_PACKAGE_VENDOR_NAME atsign-foundation)

# cmake configuration
set(CPACK_CMAKE_GENERATOR "Unix Makefiles")

# static cpack configuration
set(CPACK_PACKAGE_FILE_NAME atsdk-static)
set(CPACK_GENERATOR ZIP TGZ)
set(CPACK_INSTALL_CMAKE_PROJECTS ".;atsdk;ALL;/")

# source cpack configuration
set(CPACK_SOURCE_PACKAGE_FILE_NAME atsdk-source)
set(CPACK_SOURCE_GENERATOR TGZ ZIP)

set(CPACK_SOURCE_INSTALLED_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR};/")

# Yes, you need 4 * '\' to escape literal '.'
set(
  CPACK_SOURCE_IGNORE_FILES
  # directories
  "/\\\\.cache/"
  "/\\\\.git/"
  "/\\\\.github/"
  "/\\\\.jj/"
  "/\\\\.vscode/"
  "/CMakeFiles/"
  "/docs/"
  "/build/"
  "/generators/"
  # root files
  "/\\\\.clang-format"
  "/\\\\.clang-tidy"
  "/\\\\.clangd"
  "/just.env"
  "/just.template.env"
  "/justfile"
  "/valgrind.Dockerfile"
  # (Potentially) nested files
  "\\\\.DS_Store"
  "\\\\.gitignore"
  "compile_commands.json"
)

set(CPACK_INSTALL_SCRIPT "${CMAKE_CURRENT_BINARY_DIR}/CPackSourceDeps.cmake")
configure_file(
  "${CMAKE_SOURCE_DIR}/cmake/CPackSourceDeps.cmake"
  "CPackSourceDeps.cmake"
  @ONLY
)

include(CPack)
