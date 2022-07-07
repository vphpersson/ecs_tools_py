from re import sub as re_sub
from collections import defaultdict
from gzip import decompress as gzip_decompress
from datetime import datetime
from typing import Final, Optional, Type, Sequence, TypeVar, cast, Any
from re import compile as re_compile, Pattern as RePattern
from logging import LogRecord, WARNING, ERROR, CRITICAL, Handler
from pathlib import PurePath
from traceback import format_tb
from textwrap import dedent
from errno import errorcode
from json import dumps as json_dumps
from sys import exc_info as sys_exc_info
from inspect import currentframe, getframeinfo
from ipaddress import IPv4Address, IPv6Address

from ecs_py import Log, LogOrigin, LogOriginFile, Error, Base, Event, Process, ProcessThread, Http, HttpRequest, \
    HttpRequestBody, URL, UserAgent as ECSUserAgent, UserAgentDevice, OS, Network, Client
from psutil import boot_time as psutil_boot_time
from string_utils_py import to_snake_case
from http_lib.parse.uri import parse_uri, parse_query_string, ParsedURI
from http_lib.parse.header.forwarded import parse_forwarded_header_value, NodeForwardedElement
from public_suffix.structures.public_suffix_list_trie import PublicSuffixListTrie
from user_agents import parse as user_agents_parse
from user_agents.parsers import UserAgent
from magic import from_buffer as magic_from_buffer

from ecs_tools_py.system import entry_from_system
from ecs_tools_py.structures import SigningInformation

_DT_TIMEZONE_PATTERN: Final[RePattern] = re_compile(pattern=r'^(.{3})(.{2}).*$')

# NOTE: May need to be maintained.
_RESERVED_LOG_RECORD_KEYS: Final[set[str]] = {
    'args', 'created', 'exc_info', 'exc_text', 'filename', 'funcName', 'levelname', 'levelno', 'lineno', 'module',
    'msecs', 'msg', 'name', 'pathname', 'process', 'processName', 'relativeCreated', 'stack_info', 'thread',
    'threadName'
}


def url_entry_from_string(url: str, public_suffix_list_trie: PublicSuffixListTrie | None = None) -> URL:
    """
    Produce an ECS URL entry from a URL string.

    :param url: An URL string from which to generate an ECS URL entry.
    :param public_suffix_list_trie: A Public Suffix List trie that enables additional parsing of the URL.
    :return: An ECS URL entry produced from a URL string.
    """

    parsed_uri: ParsedURI = parse_uri(uri_string=url, public_suffix_list_trie=public_suffix_list_trie)

    # NOTE: `query_keys` and `query_values` are non-standard.
    query_key_value_pairs: list[tuple[str, str]] = parse_query_string(query_string=parsed_uri.query or '')

    return URL(
        domain=parsed_uri.host or None,
        extension=parsed_uri.extension or None,
        fragment=parsed_uri.fragment or None,
        full=url if (parsed_uri.scheme and parsed_uri.host) else None,
        original=url or None,
        password=parsed_uri.password or None,
        path=parsed_uri.path or None,
        port=parsed_uri.port if parsed_uri.port is not None else None,
        query=parsed_uri.query or None,
        registered_domain=parsed_uri.registered_domain or None,
        scheme=parsed_uri.scheme or None,
        subdomain=parsed_uri.subdomain or None,
        top_level_domain=parsed_uri.top_level_domain or None,
        username=parsed_uri.username or None,
        query_keys=[key for key, _ in query_key_value_pairs] or None,
        query_values=[value for _, value in query_key_value_pairs] or None
    )


def user_agent_entry_from_string(
    user_agent_string: Optional[str],
    raise_exception: bool = False
) -> Optional[ECSUserAgent]:
    """
    Produce an ECS UserAgent entry from a user agent string.

    :param user_agent_string: The user agent string from which to produce an ECS UserAgent entry.
    :param raise_exception: Whether to raise an exception if the parsing of the string fails.
    :return: An ECS UserAgent entry produced from the user agent string.
    """

    if not user_agent_string:
        return None

    ecs_user_agent = ECSUserAgent(original=user_agent_string)

    try:
        user_agent: UserAgent = user_agents_parse(user_agent_string=user_agent_string)
    except Exception as e:
        if raise_exception:
            raise e
    else:
        ecs_user_agent.device = UserAgentDevice(
            name=user_agent.device.family
        ) if user_agent.device.family != 'Other' else None
        ecs_user_agent.name = user_agent.browser.family
        ecs_user_agent.os = OS(
            family=user_agent.os.family,
            version=user_agent.os.version_string
        )
        ecs_user_agent.version = user_agent.browser.version_string

    return ecs_user_agent


def entry_from_http_request(
    raw_request_line: bytes,
    raw_headers: bytes,
    raw_body: Optional[bytes],
    use_forwarded_header: bool = False,
    include_decompressed_body: bool = False,
    public_suffix_list_trie: PublicSuffixListTrie | None = None
) -> Base:
    """
    Produce a ECS Base entry from the raw components of an HTTP request.

    :param raw_request_line: The raw request line of an HTTP request.
    :param raw_headers: The raw headers of an HTTP request.
    :param raw_body: The raw body of an HTTP request.
    :param use_forwarded_header: Whether to parse the `Forwarded` HTTP header.
    :param include_decompressed_body: Whether to include a decompressed version of the body.
    :param public_suffix_list_trie: A Public Suffix List trie, which enables additional parsing of the path.
    :return: ECS entries produced from the components of a raw HTTP request.
    """

    method: bytes
    path: bytes
    http_version_str: bytes
    method, path, http_version_str = raw_request_line.rstrip().split(b' ')

    # TODO: Maybe this could be put somewhere else. Maybe a separate HTTP library?
    headers: dict[str, list[str]] = defaultdict(list)
    for header_line_bytes in raw_headers.splitlines():
        header_line_bytes = header_line_bytes.rstrip()
        if not header_line_bytes:
            break

        name: bytes
        value: bytes

        name, value = header_line_bytes.split(sep=b': ', maxsplit=1)
        headers[name.decode().replace('-', '_').lower()].append(value.decode())

    network_entry = Network()
    client_entry = Client()

    if use_forwarded_header and (forwarded_value_list := headers.get('forwarded')):
        forwarded_elements: list[NodeForwardedElement] = parse_forwarded_header_value(
            forwarded_value=next(iter(forwarded_value_list)),
            use_node=True
        )

        if (first_forwarded_element := next(iter(forwarded_elements), None)) and first_forwarded_element.for_value:
            for_host: str | IPv4Address | IPv6Address
            for_port: int | None
            for_host, for_port = first_forwarded_element.for_value

            client_entry.port = for_port

            if isinstance(for_host, (IPv4Address, IPv6Address)):
                network_entry.forwarded_ip = str(for_host)
                client_entry.ip = str(for_host)

    request_mime_type = magic_from_buffer(buffer=(raw_body or b''), mime=True).lower()

    include_request_content: bool = 'octet-stream' not in (request_mime_type or '')

    decompressed_request_content: bytes = b''
    if request_mime_type == 'application/gzip':
        try:
            decompressed_request_content: bytes = gzip_decompress(data=raw_body)
        except:
            pass
        else:
            decompressed_request_content_mime_type = magic_from_buffer(
                buffer=(decompressed_request_content or b''),
                mime=True
            ).lower()

            include_decompressed_body = (
                include_decompressed_body and 'octet-stream' not in (decompressed_request_content_mime_type or '')
            )

    return Base(
        client=client_entry,
        http=Http(
            request=HttpRequest(
                body=HttpRequestBody(
                    bytes=(len(raw_body) if raw_body is not None else 0),
                    content=raw_body.decode() if include_request_content else None,
                    decompressed_content=(
                        decompressed_request_content.decode(encoding='utf-8', errors='surrogateescape') or None
                    ) if include_decompressed_body else None
                ),
                headers=dict(headers) or None,
                bytes=(
                    len(raw_headers) + (len(raw_body) if raw_body is not None else 0)
                ),
                mime_type=request_mime_type if raw_body else None,
                content_type_mime_type=[
                    re_sub(pattern=r'; charset=.+$', repl='', string=content_type)
                    for content_type in (headers.get('content_type') or [])
                ] or None,
                method=method.decode().upper(),
                referrer=headers.get('referer')
            ),
            version=http_version_str.removeprefix(b'HTTP/').decode()
        ),
        url=url_entry_from_string(url=path.decode(), public_suffix_list_trie=public_suffix_list_trie),
        network=network_entry,
        user_agent=user_agent_entry_from_string(user_agent_string=headers.get('user-agent'))
    )


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
        id=errorcode[errno_code] if (errno_code := getattr(exception_value, 'errno', None)) is not None else None
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
    base.event.dataset = record.name.split('.')[0]

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


def _dumps_function(obj: Any):
    if isinstance(obj, datetime):
        return obj.isoformat()

    raise TypeError


def _dataset_from_provider_name(provider_name: str) -> str:
    """
    Generated a value for `event.dataset` from the provider name.

    An accepted value shall contain only alphanumeric characters or underscores.

    :param provider_name: The name of the provider from which to generate a candidate `event.dataset` value.
    :return: A candidate `event.dataset` value.
    """

    return ''.join(character for character in to_snake_case(provider_name) if character.isalnum() or character == '_')


_T = TypeVar('_T', bound=Handler)


def make_log_handler(
    base_class: Type[_T],
    generate_field_names: Optional[Sequence[str]] = None,
    provider_name: Optional[str] = None,
    main_dataset_fallback: Optional[str] = None,
    signing_information: Optional[SigningInformation] = None
) -> Type[_T]:
    """
    Create a log handler that inherits from the provided base class and emits records in the ECS format.

    :param base_class: A `logging.Handler` class from the log handler to be created should inherit from.
    :param generate_field_names: A sequence of field names for field-values to be generated to complement the ones
        derived from the `logging.LogRecord` instances. A value of `None` indicates that all field-values that are
        supported should be generated.
    :param provider_name: The name of the source of the event.
    :param main_dataset_fallback: A value to be used for `event.dataset` in case its generated value is "__main__".
    :param signing_information: Information needed for signing log record messages. Provision implies use of signing.
    :return: A log handler that inherits from the provided base class and emits records in the ECS format.
    """

    class ECSLoggerHandler(base_class):

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)

            self._generate_field_names = generate_field_names
            self._provider_name = provider_name
            self._sequence_number = 0

        @property
        def logger(self) -> str:
            return f'{self.__class__.__module__}.{self.__class__.__qualname__}'

        @staticmethod
        def _sign(message: str, log_entry_dict: dict[str, Any]) -> str:
            log_entry_dict['event']['hash'] = signing_information.sign_function(
                signing_information.private_key,
                signing_information.hash_function(message.encode())
            ).hex()

            return json_dumps(obj=log_entry_dict, sort_keys=True, default=_dumps_function)

        def _get_sequence_number(self) -> int:
            """Claim a sequence number and increment."""
            sequence_number = self._sequence_number
            self._sequence_number += 1
            return sequence_number

        def _emit_signing_error_message(self, record_name: str) -> None:
            frameinfo = getframeinfo(currentframe())

            super().emit(
                record=LogRecord(
                    name=record_name,
                    level=ERROR,
                    pathname=frameinfo.filename,
                    lineno=frameinfo.lineno,
                    msg=json_dumps(
                        obj=Base(
                            error=error_entry_from_exc_info(exc_info=sys_exc_info()),
                            message='An error occurred when attempting to sign a log record message.',
                            log=Log(logger=self.logger),
                            event=Event(
                                provider=provider_name,
                                dataset='ecs_tools_py',
                                sequence=self._get_sequence_number()
                            )
                        ).to_dict(),
                        sort_keys=True,
                        default=_dumps_function
                    ),
                    func=frameinfo.function,
                    args=None,
                    exc_info=None
                )
            )

        def _emit_generate_fields_error_message(self, record_name: str) -> None:
            frameinfo = getframeinfo(currentframe())

            log_entry_dict: dict[str, Any] = Base(
                error=error_entry_from_exc_info(exc_info=sys_exc_info()),
                message='An error occurred when generating fields for a log record.',
                log=Log(logger=self.logger),
                event=Event(
                    provider=provider_name,
                    dataset='ecs_tools_py',
                    sequence=self._get_sequence_number()
                )
            ).to_dict()

            message: str = json_dumps(obj=log_entry_dict, sort_keys=True, default=_dumps_function)

            if signing_information is not None:
                try:
                    message: str = self._sign(message=message, log_entry_dict=log_entry_dict)
                except:
                    self._emit_signing_error_message(record_name=record_name)

            super().emit(
                record=LogRecord(
                    name=record_name,
                    level=ERROR,
                    pathname=frameinfo.filename,
                    lineno=frameinfo.lineno,
                    msg=message,
                    func=frameinfo.function,
                    args=None,
                    exc_info=None
                )
            )

        def emit(self, record: LogRecord) -> None:
            """
            Emit a log record.

            :param record: A log record to be emitted.
            :return: None
            """

            try:
                ecs_log_entry = entry_from_log_record(record=record, field_names=self._generate_field_names)
            except:
                self._emit_generate_fields_error_message(record_name=record.name)
                ecs_log_entry = entry_from_log_record(record=record, field_names=[])

            # Assign information about the log and provider that was provided to the make function, and a sequence
            # number.

            cast(Log, ecs_log_entry.get_field_value(field_name='log', create_namespaces=True)).logger = self.logger

            ecs_log_entry_event: Event = cast(
                Event,
                ecs_log_entry.get_field_value(
                    field_name='event',
                    create_namespaces=True
                )
            )
            ecs_log_entry_event.provider = self._provider_name
            ecs_log_entry_event.sequence = self._get_sequence_number()

            # Set `event.dataset` to a proper value and determine the name of the namespace that will store extra data.

            if ecs_log_entry_event.dataset == '__main__':
                if main_dataset_fallback:
                    ecs_log_entry_event.dataset = extra_data_namespace_name = main_dataset_fallback
                elif ecs_log_entry_event.provider and (provider_name_dataset := _dataset_from_provider_name(provider_name=ecs_log_entry_event.provider)):
                    ecs_log_entry_event.dataset = extra_data_namespace_name = provider_name_dataset
                else:
                    extra_data_namespace_name = 'data'
            elif not ecs_log_entry_event.dataset:
                if ecs_log_entry_event.provider and (provider_name_dataset := _dataset_from_provider_name(provider_name=ecs_log_entry_event.provider)):
                    ecs_log_entry_event.dataset = extra_data_namespace_name = provider_name_dataset
                else:
                    extra_data_namespace_name = 'data'
            else:
                extra_data_namespace_name = ecs_log_entry_event.dataset

            log_entry_dict: dict[str, Any] = ecs_log_entry.to_dict()

            # Populate a namespace with data provided in the `extra` parameter.

            if extra_keys := set(record.__dict__.keys()) - _RESERVED_LOG_RECORD_KEYS:
                log_entry_dict[extra_data_namespace_name] = {key: record.__dict__[key] for key in extra_keys}

            # Create the JSON-string representation of the log record's dictionary, which constitutes the log message.

            message: str = json_dumps(obj=log_entry_dict, sort_keys=True, default=_dumps_function)

            # Sign the message if signing information has been provided

            if signing_information is not None:
                try:
                    message: str = self._sign(message=message, log_entry_dict=log_entry_dict)
                except:
                    self._emit_signing_error_message(record_name=record.name)

            record.msg = message

            # Clear the record of exception information, which has already been handled, that would confuse the parent
            # `emit` method.

            record.exc_info = None
            record.exc_text = None
            record.stack_info = None

            super().emit(record=record)

    return ECSLoggerHandler
