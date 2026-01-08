"""
APILeak OWASP Enhancement Setup
Enterprise-grade API fuzzing and OWASP testing tool
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="apileak-owasp-enhancement",
    version="0.1.0",
    author="APILeak Team",
    author_email="team@apileak.com",
    description="Enterprise-grade API fuzzing and OWASP testing tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/apileak/owasp-enhancement",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.11",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "apileak=apileaks:cli",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["wordlists/*.txt", "config/*.yaml", "templates/*"],
    },
)