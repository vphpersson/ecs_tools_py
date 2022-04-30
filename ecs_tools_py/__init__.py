from datetime import datetime
from typing import Final, Optional, Type, Sequence
from re import compile as re_compile, Pattern as RePattern
from logging import LogRecord, WARNING, ERROR, CRITICAL
from pathlib import PurePath
from traceback import format_tb
from textwrap import dedent

from ecs_py import Log, LogOrigin, LogOriginFile, Error, Base, Event, Process, ProcessThread
from psutil import boot_time as psutil_boot_time

from ecs_tools_py.system import entry_from_system

_DT_TIMEZONE_PATTERN: Final[RePattern] = re_compile(pattern=r'^(.{3})(.{2}).*$')


def event_timezone_from_datetime(dt: datetime) -> str:
    """
    Produce a timezone value that is compatible with ECS from a `datetime` instance.

    :param dt: A `datetime` instance whose timezone value to produce.
    :return: An ECS-compatible timezone value produced from the provided `datetime` instance.
    """

    return _DT_TIMEZONE_PATTERN.sub(repl=r'\1:\2', string=f'{dt:%z}')


def error_entry_from_exc_info(exc_info) -> Error:
    """
    Produce an ECS `Error` entry from exception info.

    :param exc_info: Exception info from which to produce an ECS `Error` entry.
    :return: An ECS `Error` entry produced from the provided exception info.
    """

    exception_type: Type[Exception]
    exception_value: Exception

    exception_type, exception_value, exception_traceback = exc_info

    return Error(
        message=str(exception_value),
        stack_trace=dedent(''.join(format_tb(exception_traceback))).rstrip(),
        type=f'{exception_type.__module__}.{exception_type.__qualname__}',
        id=getattr(exception_value, 'errno', None)
    )


def entry_from_log_record(record: LogRecord, field_names: Optional[Sequence[str]] = None) -> Base:
    """
    Produce an ECS `Base` entry from a log record.

    :param record: A log record from which to produce an ECS `Base` entry.
    :param field_names: A sequence of fields to be added (generated) to the ECS entry, that are not directly
        extracted from the log record.
    :return: An ECS `Base` entry produced from a log record.
    """

    field_names = set(field_names) if field_names is not None else None

    if field_names is None:
        add_event_timezone = True
        add_host_uptime = True
        add_process_uptime = True
    else:
        if (field_name := 'event.timezone') in field_names:
            field_names.remove(field_name)
            add_event_timezone = True
        else:
            add_event_timezone = False

        if (field_name := 'host.uptime') in field_names:
            field_names.remove(field_name)
            add_host_uptime = True
        else:
            add_host_uptime = False

        if (field_name := 'process.uptime') in field_names:
            field_names.remove(field_name)
            add_process_uptime = 'process.start' in field_names
        else:
            add_process_uptime = False

    base: Base = entry_from_system(field_names=field_names)

    base.log = base.log or Log()
    base.log.origin = base.log.origin or LogOrigin()
    base.log.origin.file = base.log.origin.file or LogOriginFile()
    base.log.origin.file.path = record.pathname
    base.log.origin.file.name = PurePath(record.pathname).name
    base.log.origin.file.line = record.lineno
    base.log.origin.function = record.funcName
    base.log.level = record.levelname

    if record.levelno in {WARNING, ERROR, CRITICAL}:
        base.error = base.error or Error()

        if record.exc_info:
            exc_info_error_entry: Error = error_entry_from_exc_info(exc_info=record.exc_info)

            base.error.message = exc_info_error_entry.message
            base.error.stack_trace = exc_info_error_entry.stack_trace
            base.error.type = exc_info_error_entry.type
            base.error.id = exc_info_error_entry.id
        else:
            base.error.message = record.msg

    base.event = base.event or Event()
    base.event.created = datetime.fromtimestamp(record.created).astimezone()

    if add_event_timezone:
        base.event.timezone = event_timezone_from_datetime(dt=base.event.created)

    if add_host_uptime:
        base.get_field_value(
            field_name='host',
            create_namespaces=True
        ).uptime = (base.event.created - datetime.fromtimestamp(psutil_boot_time()).astimezone()).seconds

    if add_process_uptime and (process_start := base.get_field_value(field_name='process.start')):
        base.get_field_value(
            field_name='process',
            create_namespaces=True
        ).uptime = (base.event.created - process_start).seconds

    base.process = base.process or Process()
    base.process.title = record.processName
    base.process.pid = record.process
    base.process.thread = base.process.thread or ProcessThread()
    base.process.thread.id = record.thread
    base.process.thread.name = record.threadName

    base.message = record.msg

    return base
