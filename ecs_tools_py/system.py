from logging import getLogger, Logger
from typing import Final, Callable, Any, Sequence
from socket import gethostname as socket_gethostname, getfqdn as socket_getfqdn
from sys import orig_argv as sys_orig_argv
from platform import release as platform_release, system as platform_system, machine as platform_machine
from functools import cache
from collections import defaultdict
from dataclasses import fields as dataclasses_fields
from os import getcwd as os_getcwd, getppid as os_getppid, getpid as os_getpid
from shlex import join as shlex_join
from pathlib import PurePath
from datetime import datetime
from re import compile as re_compile, Pattern as RePattern

# NOTE: It is necessary to import the whole module in order to retrieve classes from it dynamically.
import ecs_py
from ecs_py import Base, ECSEntry

from ecs_tools_py.exceptions import UnexpectedFieldsError, NamespaceFieldIsNotDataclassError, UnhandledDerivedFieldError


LOG: Final[Logger] = getLogger(__name__)

_OPTIONAL_TYPE_PATTERN: Final[RePattern] = re_compile(pattern=r'^([^ |]+)\s*\|\s*None$')

# host


@cache
def make_host_architecture() -> str | None:
    return platform_machine() or None


@cache
def make_host_hostname() -> str:
    return socket_gethostname()


@cache
def make_host_name() -> str:
    return socket_getfqdn()


# os


@cache
def make_os_kernel() -> str | None:
    return platform_release() or None


@cache
def make_os_type() -> str | None:
    return system.lower() if (system := platform_system()) else None

# process


@cache
def make_process_args() -> list[str]:
    return sys_orig_argv


def make_process_executable() -> str | None:
    try:
        from psutil import Process as PsutilProcess
        return PsutilProcess().exe()
    except ImportError:
        return None


def make_process_start() -> datetime | None:
    try:
        from psutil import Process as PsutilProcess
        return datetime.fromtimestamp(PsutilProcess().create_time()).astimezone()
    except ImportError:
        return None


def make_process_pid() -> int:
    return os_getpid()


def make_process_working_directory() -> str:
    return os_getcwd()


def make_process_parent_pid() -> int:
    return os_getppid()


def make_process_user_name() -> str | None:
    try:
        from psutil import Process as PsutilProcess
        process_user_name = PsutilProcess().username()

        try:
            from os import getuid
            if process_user_name == str(getuid()):
                return None
        except ImportError:
            pass

        return process_user_name
    except:
        return None


def make_process_user_id() -> str | None:
    try:
        from os import getuid
        return str(getuid())
    except ImportError:
        return None


def make_process_user_effective_name() -> str | None:
    try:
        from pwd import getpwuid
        return getpwuid(PsutilProcess().uids().effective).pw_name
    except ImportError:
        return None


def make_process_user_effective_id() -> str | None:
    try:
        from os import geteuid
        return str(geteuid())
    except ImportError:
        return None


def make_process_group_id() -> str | None:
    try:
        from os import getgid

        return str(getgid())
    except ImportError:
        return None


def make_process_group_name() -> str | None:
    try:
        from os import getgid
        from grp import getgrgid

        return getgrgid(getgid()).gr_name
    except ImportError:
        return None


def make_process_group_effective_id() -> str | None:
    try:
        from os import getegid

        return str(getegid())
    except ImportError:
        return None


def make_progress_group_effective_name() -> str | None:
    try:
        from os import getegid
        from grp import getgrgid

        return getgrgid(getegid()).gr_name
    except ImportError:
        return None


def derive_process_arg_count(args: list[str]) -> int:
    return len(args)


def derive_process_command_line(args: list[str]) -> str:
    return shlex_join(args)


def derive_process_name(executable: str) -> str:
    return PurePath(executable).name


FIELD_TO_MAKE_FUNCTION: Final[dict[str, Callable[[], Any] | None]] = {
    'host.architecture': make_host_architecture,
    'host.hostname': make_host_hostname,
    'host.name': make_host_name,
    'host.os.kernel': make_os_kernel,
    'host.os.type': make_os_type,
    'log.origin.process.args': make_process_args,
    'log.origin.process.arg_count': None,
    'log.origin.process.command_line': None,
    'log.origin.process.executable': make_process_executable,
    'log.origin.process.name': None,
    'log.origin.process.pid': make_process_pid,
    'log.origin.process.start': make_process_start,
    'log.origin.process.parent.pid': make_process_parent_pid,
    'log.origin.process.user.id': make_process_user_id,
    'log.origin.process.user.name': make_process_user_name,
    'log.origin.process.user.effective.id': make_process_user_effective_id,
    'log.origin.process.user.effective.name': make_process_user_effective_name,
    'log.origin.process.group.id': make_process_group_id,
    'log.origin.process.group.name': make_process_group_name,
    'log.origin.process.group.effective.id': make_process_group_effective_id,
    'log.origin.process.group.effective.name': make_progress_group_effective_name,
    'log.origin.process.working_directory': make_process_working_directory
}

SUPPORTED_FIELD_NAMES: Final[set[str]] = set(FIELD_TO_MAKE_FUNCTION.keys())


def entry_from_system(field_names: Sequence[str | None] = None) -> Base:
    """
    Produce an ECS `Base` entry from information that can be gathered from the system.

    :param field_names: A sequence of field names whose corresponding values are to be gathered from the system.
    :return: An ECS `Base` entry storing the gathered field-values.
    """

    field_names: set[str] = set(field_names) if field_names is not None else SUPPORTED_FIELD_NAMES

    if provided_unsupported_fields := (field_names - SUPPORTED_FIELD_NAMES):
        raise UnexpectedFieldsError(unsupported_fields=provided_unsupported_fields)

    def populate_namespace_entry(
        namespace_storage: ECSEntry,
        namespace_field_names: set[str],
        namespace_stack: list[str]
    ) -> None:
        """
        Populate a namespace with gathered values.

        :param namespace_storage: A namespace instance to store gathered values.
        :param namespace_field_names: Names of fields within the current namespace hierarchy to be populated with
            gathered values.
        :param namespace_stack: A stack with which to build the full field name, in order to look up and call the
            corresponding "make function".
        :return: None
        """

        sub_namespace_to_field_names: defaultdict[str, set[str]] = defaultdict(set)
        derived_full_field_names: list[str] = []

        for namespace_field_name in namespace_field_names:
            if '.' in namespace_field_name:
                sub_namespace, sub_namespace_field_name = namespace_field_name.split(sep='.', maxsplit=1)
                sub_namespace_to_field_names[sub_namespace].add(sub_namespace_field_name)
            else:
                full_field_name = '.'.join(namespace_stack) + f'.{namespace_field_name}'
                make_function = FIELD_TO_MAKE_FUNCTION[full_field_name]
                if make_function is None:
                    derived_full_field_names.append(full_field_name)
                    continue

                try:
                    value = make_function()
                except:
                    LOG.exception('Make value generation error.')
                else:
                    if value is not None:
                        setattr(namespace_storage, namespace_field_name, value)

        for entry_class_field in dataclasses_fields(namespace_storage):
            if entry_class_field.name not in sub_namespace_to_field_names:
                continue

            entry_class_field_type = entry_class_field.type
            if isinstance(entry_class_field_type, str):
                entry_class_field_type = getattr(
                    ecs_py,
                    _OPTIONAL_TYPE_PATTERN.sub(repl=r'\1', string=entry_class_field_type)
                )

            if issubclass(entry_class_field_type, ECSEntry):
                entry_class_field_storage = entry_class_field_type()

                namespace_stack.append(entry_class_field.name)
                populate_namespace_entry(
                    namespace_field_names=sub_namespace_to_field_names[entry_class_field.name],
                    namespace_storage=entry_class_field_storage,
                    namespace_stack=namespace_stack
                )
                namespace_stack.pop()

                if any(getattr(entry_class_field_storage, field.name) is not None for field in dataclasses_fields(entry_class_field_storage)):
                    setattr(namespace_storage, entry_class_field.name, entry_class_field_storage)
            else:
                # TODO: Change error name.
                raise NamespaceFieldIsNotDataclassError(field='.'.join(namespace_stack) + f'.{entry_class_field.name}')

        for derived_full_field_name in derived_full_field_names:
            derived_short_field_name = derived_full_field_name.split('.')[-1]

            try:
                value = None
                match derived_full_field_name:
                    case 'log.origin.process.arg_count':
                        if process_args := getattr(namespace_storage, 'args', None):
                            value = derive_process_arg_count(args=process_args)
                    case 'log.origin.process.command_line':
                        if process_args := getattr(namespace_storage, 'args', None):
                            value = derive_process_command_line(args=process_args)
                    case 'log.origin.process.process.name':
                        if process_executable := getattr(namespace_storage, 'executable', None):
                            value = derive_process_name(executable=process_executable)
                    case _:
                        raise UnhandledDerivedFieldError(field=derived_full_field_name)
            except:
                LOG.exception('Derive value generation error.')
                continue
            else:
                if value is not None:
                    setattr(namespace_storage, derived_short_field_name, value)

    log_entry = Base()

    populate_namespace_entry(namespace_storage=log_entry, namespace_field_names=field_names, namespace_stack=[])

    return log_entry
