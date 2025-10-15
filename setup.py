from setuptools import setup, find_packages

setup(
    name="kmim",
    version="1.0.0",
    packages=["cli"],
    install_requires=[
        "bcc>=0.18.0",
        "rich>=10.0.0",
        "pyelftools>=0.27",
    ],
    entry_points={
        'console_scripts': [
            'kmim=cli.kmim:main',
        ],
    },
    author="Software Security Lab",
    author_email="lab@hprcse.org",
    description="Kernel Module Integrity Monitor using eBPF",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/hprcse/kmim",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Topic :: System :: Systems Administration",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
)
