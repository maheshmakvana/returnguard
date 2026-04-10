from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="returnguard",
    version="1.2.0",
    author="",
    description="Returns fraud detection for retail and eCommerce — wardrobing, serial returner, refund anomaly detection, behavioral fingerprinting, policy simulation",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/returnguard-py/returnguard",
    packages=find_packages(exclude=["tests*"]),
    python_requires=">=3.8",
    install_requires=[
        "pydantic>=2.0",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Intended Audience :: Developers",
    ],
    keywords=[
        "returns fraud detection", "ecommerce fraud", "retail fraud",
        "wardrobing detection", "return policy abuse", "refund fraud",
        "fraud scoring python", "return rate analysis",
        "customer fraud detection", "shopify fraud detection",
        "refund anomaly detection python", "behavioral fingerprinting python",
        "return policy simulator", "customer risk profiling",
        "ecommerce returns analytics", "fraud signal explainer",
    ],
)
