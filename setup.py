from setuptools import setup, find_packages

setup(
    name='ecs_tools_py',
    version='0.89',
    packages=find_packages(),
    install_requires=[
        'ecs_py @ git+https://github.com/vphpersson/ecs_py.git#egg=ecs_py',
        'string_utils_py @ git+https://github.com/vphpersson/string_utils_py.git#egg=string_utils_py',
        'http_lib @ git+https://github.com/vphpersson/http_lib.git#egg=http_lib',
        'public_suffix @ git+https://github.com/vphpersson/public_suffix.git#egg=public_suffix',
        'psutil',
        'user-agents',
        'ua-parser',
        'python-magic'
    ]
)
