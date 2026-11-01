# Package metadata lives in pyproject.toml; this file only declares the C extension.
# Build requirements: a C compiler, Python headers and libgcrypt-dev (libgcrypt20-dev).
from setuptools import Extension, setup

zigbee_crypt = Extension(
    "zigbee_crypt",
    sources=["zigbee_crypt/zigbee_crypt.c"],
    libraries=["gcrypt"],
    include_dirs=["/usr/local/include", "/usr/include", "/sw/include/", "zigbee_crypt"],
    library_dirs=["/usr/local/lib", "/usr/lib", "/sw/var/lib/"],
)

setup(ext_modules=[zigbee_crypt])
