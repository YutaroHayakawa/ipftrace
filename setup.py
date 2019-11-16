from setuptools import setup

setup(
    name="ipftrace",
    version="0.0.1",
    author="Yutaro Hayakawa",
    author_email="yhayakawa3720@gmail.com",
    install_requires=["click", "pyyaml", "tabulate"],
    packages=["ipftrace"],
    package_data={"ipftrace": ["ipftrace.bpf.c"]},
    entry_points={
        "console_scripts": [
            "ipftrace=ipftrace.ipftrace:main",
        ]
    },
    python_requires=">=3.7",
)
