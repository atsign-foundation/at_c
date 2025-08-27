# This Conanfile is presently used to create the at_c SBOM and isn't
# used to generate CMake builds or anything else.

from conan import ConanFile
from conan.tools.cmake import CMakeToolchain, CMake, cmake_layout, CMakeDeps


class at_cRecipe(ConanFile):
    name = "at_c"
    version = "0.3.4"
    package_type = "library"

    # Optional metadata
    license = "BSD-3-Clause"
    author = "atsign-foundation"
    url = "https://github.com/atsign-foundation/at_c"
    description = "Cross-platform C implementation of the atSDK for SOC & embedded devices"

    # Binary configuration
    settings = "os", "compiler", "build_type", "arch"
    options = {"shared": [True, False], "fPIC": [True, False]}
    default_options = {"shared": False, "fPIC": True}

    # Sources are located in the same place as this recipe, copy them to the recipe
    exports_sources = "CMakeLists.txt", "src/*", "include/*"

    def config_options(self):
        if self.settings.os == "Windows":
            self.options.rm_safe("fPIC")

    def configure(self):
        if self.options.shared:
            self.options.rm_safe("fPIC")

    def layout(self):
        cmake_layout(self)

    def generate(self):
        deps = CMakeDeps(self)
        deps.generate()
        tc = CMakeToolchain(self)
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    def package_info(self):
        self.cpp_info.libs = ["at_c"]

    def requirements(self):
        self.requires("mbedtls/3.6.4")
        self.requires("cjson/1.7.18")
