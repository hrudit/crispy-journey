
from setuptools import setup

setup(
    name='flights-all',
    version='0.1.0',
    packages=['flights'],
    include_package_data=True,
    install_requires=[
        'arrow',
        'bs4',
        'Flask',
        'html5validator',
        'requests',
    ],
    python_requires='>=3.6',
)
