"""
Setup configuration for LLM-Guided Explainable IDS
Install package with: pip install -e .
"""

from setuptools import setup, find_packages
import os

# Read long description from README
def read_long_description():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    requirements = []
    if os.path.exists("requirements.txt"):
        with open("requirements.txt", "r", encoding="utf-8") as fh:
            requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
    return requirements

setup(
    name="llm-guided-ids",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="An explainable intrusion detection system powered by machine learning and LLMs",
    long_description=read_long_description(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/llm-guided-ids",
    project_urls={
        "Bug Tracker": "https://github.com/yourusername/llm-guided-ids/issues",
        "Documentation": "https://github.com/yourusername/llm-guided-ids/wiki",
        "Source Code": "https://github.com/yourusername/llm-guided-ids",
    },
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Science/Research",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "isort>=5.12.0",
            "mypy>=1.0.0",
            "pre-commit>=3.0.0",
        ],
        "docs": [
            "sphinx>=5.0.0",
            "sphinx-rtd-theme>=1.2.0",
            "sphinxcontrib-napoleon>=0.7",
        ],
        "gpu": [
            "tensorflow-gpu>=2.13.0",
        ],
        "all": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "sphinx>=5.0.0",
            "sphinx-rtd-theme>=1.2.0",
            "tensorflow-gpu>=2.13.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "ids-train=src.main_pipeline:train_models_cli",
            "ids-detect=src.main_pipeline:detect_cli",
            "ids-dashboard=src.dashboard:launch_dashboard",
            "ids-explain=src.llm_explainer:explain_cli",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["config/*.yaml", "data/sample/*"],
    },
    zip_safe=False,
    keywords=[
        "intrusion detection",
        "network security",
        "machine learning",
        "deep learning",
        "explainable AI",
        "LLM",
        "cybersecurity",
        "anomaly detection",
    ],
    platforms=["any"],
)