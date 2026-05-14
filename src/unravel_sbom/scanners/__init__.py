from unravel_sbom.scanners.cmake import CMakeScanner
from unravel_sbom.scanners.conan import ConanfilePyScanner, ConanfileTxtScanner
from unravel_sbom.scanners.makefile import MakefileScanner
from unravel_sbom.scanners.npm import PackageJsonScanner, PackageLockScanner
from unravel_sbom.scanners.pypi import (
    PoetryLockScanner,
    PyprojectTomlScanner,
    RequirementsTxtScanner,
)
from unravel_sbom.scanners.ros import PackageXmlScanner

ALL_SCANNERS = [
    # Lock-file scanners first: they carry exact/resolved versions
    PackageLockScanner(),
    PoetryLockScanner(),
    # Manifest scanners
    PackageJsonScanner(),
    PyprojectTomlScanner(),
    RequirementsTxtScanner(),
    ConanfileTxtScanner(),
    ConanfilePyScanner(),
    MakefileScanner(),
    CMakeScanner(),
    PackageXmlScanner(),
]
