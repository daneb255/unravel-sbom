from unravel_sbom.scanners.cargo import CargoLockScanner, CargoTomlScanner
from unravel_sbom.scanners.cmake import CMakeScanner
from unravel_sbom.scanners.conan import ConanfilePyScanner, ConanfileTxtScanner
from unravel_sbom.scanners.golang import GoModScanner, GoSumScanner
from unravel_sbom.scanners.gradle import GradleScanner
from unravel_sbom.scanners.makefile import MakefileScanner
from unravel_sbom.scanners.maven import PomXmlScanner
from unravel_sbom.scanners.npm import PackageJsonScanner, PackageLockScanner
from unravel_sbom.scanners.nuget import NuGetScanner
from unravel_sbom.scanners.pypi import (
    PoetryLockScanner,
    PyprojectTomlScanner,
    RequirementsTxtScanner,
)
from unravel_sbom.scanners.ros import PackageXmlScanner
from unravel_sbom.scanners.rubygems import GemfileLockScanner, GemfileScanner

ALL_SCANNERS = [
    # Lock-file scanners first: they carry exact/resolved versions
    PackageLockScanner(),
    PoetryLockScanner(),
    GoSumScanner(),
    CargoLockScanner(),
    GemfileLockScanner(),
    # Manifest & build file scanners
    PackageJsonScanner(),
    PyprojectTomlScanner(),
    RequirementsTxtScanner(),
    GoModScanner(),
    CargoTomlScanner(),
    PomXmlScanner(),
    GradleScanner(),
    GemfileScanner(),
    NuGetScanner(),
    ConanfileTxtScanner(),
    ConanfilePyScanner(),
    MakefileScanner(),
    CMakeScanner(),
    PackageXmlScanner(),
]
