from setuptools import setup, find_packages

setup(
    name="vrops-inventory",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "requests>=2.25.1",
        "pyyaml>=5.4.1",
        "ansible-core>=2.11.0",
    ],
    author="Your Name",
    author_email="your.email@example.com",
    description="A Python tool to generate Ansible inventory from vROPS (Aria Operations) REST API",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://gitlab.com/your-username/vrops-inventory",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    entry_points={
        'console_scripts': [
            'vrops-inventory=vrops_inventory.src.inventory_generator:main',
        ],
    },
)