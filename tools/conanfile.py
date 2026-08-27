# This Conanfile is presently used to create the at_c SBOM and isn't
# used to generate CMake builds or anything else.

from conan import ConanFile
from conan.tools.cmake import CMakeToolchain, CMake, cmake_layout, CMakeDeps
from conan.tools.files import get


class at_cRecipe(ConanFile):
    name = "at_c"
    version = "0.3.10"
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

    def source(self):
        get(self, f"https://github.com/atsign-foundation/at_c/releases/download/v{self.version}/at_c-v{self.version}.tar.gz",
              strip_root=True)

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

    def package_info(self):
        self.cpp_info.libs = ["at_c"]

    def requirements(self):
        self.requires("mbedtls/3.6.7")
        self.requires("cjson/1.7.19")
