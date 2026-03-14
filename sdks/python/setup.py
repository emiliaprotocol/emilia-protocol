from setuptools import setup, find_packages

setup(
    name="emilia-protocol",
    version="0.1.0",
    description="Python SDK for EMILIA Protocol (EP) — the trust layer for agentic commerce.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="EMILIA Protocol",
    author_email="hello@emiliaprotocol.ai",
    url="https://github.com/emiliaprotocol/emilia-protocol",
    project_urls={
        "Documentation": "https://emiliaprotocol.ai",
        "Source": "https://github.com/emiliaprotocol/emilia-protocol/tree/main/sdks/python",
    },
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=["httpx>=0.24.0"],
    license="Apache-2.0",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Topic :: Software Development :: Libraries",
    ],
    keywords="emilia trust reputation ai-agents agentic-commerce mcp a2a",
)
