from conans import ConanFile


class MyProjectConan(ConanFile):
    name = "myproject"
    version = "1.0"
    requires = ["zlib/1.2.13", "fmt/10.1.1"]  # noqa: RUF012
    build_requires = "cmake/3.27.0"

    def requirements(self):
        self.requires("nlohmann_json/3.11.2")
