from collections import defaultdict
from datetime import datetime
from typing import Final, Type, Sequence, TypeVar, cast, Any
from re import compile as re_compile, Pattern as RePattern
from logging import LogRecord, WARNING, ERROR, CRITICAL, Handler
from pathlib import PurePath
from traceback import format_tb
from textwrap import dedent
from errno import errorcode
from json import dumps as json_dumps
from inspect import currentframe, getframeinfo
from ipaddress import IPv4Address, IPv6Address
from socket import socket as socket_class, SocketKind, AddressFamily
from dataclasses import fields as dataclasses_fields
from email.message import EmailMessage
from hashlib import md5, sha1, sha256

from ecs_py import Log, LogOrigin, LogOriginFile, Error, Base, Event, Process, ProcessThread, Http, \
    HttpRequest as ECSHttpRequest, HttpResponse as ECSHttpResponse, HttpBody, URL, UserAgent as ECSUserAgent, \
    UserAgentDevice, OS, Network, Client, Server, Destination, Source, ECSEntry, EmailAttachmentFile, Hash, \
    EmailBody
from psutil import boot_time as psutil_boot_time
from string_utils_py import to_snake_case
from http_lib.structures.message import Message as HTTPMessage, Request as HTTPRequest, Response as HTTPResponse
from http_lib.parse.uri import parse_uri, parse_query_string, ParsedURI
from http_lib.parse.header.forwarded import parse_forwarded_header_value, ParameterParsedForwardedElement
from http_lib.parse.header.content_type import parse_content_type
from http_lib.parse.host import parse_host, IPvFutureString
from http_lib.parse.content import decompress_body
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


def merge_dict_entries(*entries: dict[str, Any]) -> dict[str, Any]:
    """
    Merge dictionary entries.

    Later entries have precedence. Works recursively. A value will not be set if it is `None`.

    :param entries: Entries to be merged.
    :return: A merged dictionary entry.
    """

    master_entry: dict[str, Any] = entries[0]

    if len(entries) == 1:
        return master_entry

    def merge(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
        for key, b_value in b.items():
            if isinstance(a_value := a.get(key), dict) and isinstance(b_value, dict):
                merge(a_value, b_value)
            elif b_value is not None:
                a[key] = b_value

        return a

    for entry in entries[1:]:
        merge(master_entry, entry)

    return master_entry


_ENTRY_TYPE = TypeVar('_ENTRY_TYPE', bound=ECSEntry)


def merge_ecs_entries(*entries: _ENTRY_TYPE) -> _ENTRY_TYPE:

    master_entry: ECSEntry = entries[0]
    if len(entries) == 1:
        return master_entry

    def merge(a: _ENTRY_TYPE, b: _ENTRY_TYPE) -> _ENTRY_TYPE:

        if (a_type := type(a)) is not (b_type := type(b)):
            raise ValueError(f'The ECS entry types are not the same: "{a_type}", "{b_type}"')

        b_key_value_pairs = tuple((field.name, getattr(b, field.name)) for field in dataclasses_fields(b))

        for key, b_value in b_key_value_pairs:
            if isinstance(a_value := getattr(a, key, None), ECSEntry) and isinstance(b_value, ECSEntry):
                merge(a_value, b_value)
            elif b_value is not None:
                setattr(a, key, b_value)

        return a

    for entry in entries[1:]:
        merge(master_entry, entry)

    return master_entry


def network_entry_from_socket(socket: socket_class) -> Network:
    """
    Produce an ECS Network entry from a socket.

    :param socket: A socket from which to produce information for the ECS entry.
    :return: An ECS Network entry with information produced from a socket.
    """

    network_iana_number = socket.proto

    match socket.family:
        case AddressFamily.AF_INET:
            network_type = 'ipv4'
        case AddressFamily.AF_INET6:
            network_type = 'ipv6'
        case _:
            network_type = None

    match socket.type:
        case SocketKind.SOCK_STREAM:
            network_transport = 'tcp'
        case SocketKind.SOCK_DGRAM:
            network_transport = 'udp'
        case _:
            network_transport = None

    return Network(
        iana_number=str(network_iana_number),
        type=network_type,
        transport=network_transport
    )


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


_ECS_DESTINATION_SERVER_TYPE = TypeVar('_ECS_DESTINATION_SERVER_TYPE', bound=Type[Destination | Server])
_ECS_SOURCE_CLIENT_TYPE = TypeVar('_ECS_SOURCE_CLIENT_TYPE', bound=Type[Source | Client])


def entry_from_host_header_value(
    host_header_value: str,
    entry_type: Type[_ECS_DESTINATION_SERVER_TYPE]
) -> _ECS_DESTINATION_SERVER_TYPE:
    """
    Produce either a `Destination` or `Server` ECS entry from the `Host` HTTP header value.

    :param host_header_value: The `Host` HTTP header value to parse.
    :param entry_type: The type of ECS entry to populate with parsed values.
    :return: An ECS entry populated with parsed values.
    """

    host_name: str | IPvFutureString | IPv4Address | IPv6Address
    host_port: int | None
    host_name, host_port = parse_host(host_value=host_header_value)

    ecs_entry: _ECS_DESTINATION_SERVER_TYPE = entry_type(address=str(host_name), port=host_port)

    if isinstance(host_name, (IPv4Address, IPv6Address)):
        ecs_entry.ip = ecs_entry.address

    return ecs_entry


def entries_from_forwarded_header_value(
    forwarded_header_value: str,
    entry_type_for: Type[_ECS_SOURCE_CLIENT_TYPE],
    entry_type_host: Type[_ECS_DESTINATION_SERVER_TYPE]
) -> tuple[_ECS_SOURCE_CLIENT_TYPE | None, _ECS_DESTINATION_SERVER_TYPE | None]:
    """
    Produce a pair of ECS entries from a `Forwarded` HTTP header value.

    Only the first forwarded element is parsed.

    :param forwarded_header_value: A `Forwarded` HTTP header value to be parsed.
    :param entry_type_for: The type of ECS entry to be populated with values parsed from the "for" value.
    :param entry_type_host: The type of ECS entry to be populated with values parsed from the "host" value.
    :return: A pair of ECS entries populated with parsed values.
    """

    forwarded_elements: list[ParameterParsedForwardedElement] = parse_forwarded_header_value(
        forwarded_value=forwarded_header_value,
        parse_parameter_values=True
    )

    first_forwarded_element = next(iter(forwarded_elements), None)
    if not first_forwarded_element:
        raise ValueError('There are no elements in the provided `Forwarded` value.')

    ecs_entry_for: _ECS_SOURCE_CLIENT_TYPE | None = None

    if for_value := first_forwarded_element.for_value:
        for_host: str | IPv4Address | IPv6Address
        for_port: int | None
        for_host, for_port = for_value

        ecs_entry_for = entry_type_for(address=str(for_host), port=for_port)

        if isinstance(for_host, (IPv4Address, IPv6Address)):
            ecs_entry_for.ip = ecs_entry_for.address

    ecs_entry_host: _ECS_DESTINATION_SERVER_TYPE | None = None

    if host_value := first_forwarded_element.host_value:
        host_name: str | IPvFutureString | IPv4Address | IPv6Address
        host_port: int | None
        host_name, host_port = host_value

        ecs_entry_host = entry_type_host(address=str(host_name), port=host_port)

        if isinstance(host_name, (IPv4Address, IPv6Address)):
            ecs_entry_host.ip = ecs_entry_host.address

    return ecs_entry_for, ecs_entry_host


def user_agent_entry_from_string(
    user_agent_string: str,
    raise_exception: bool = False
) -> ECSUserAgent | None:
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
            name=user_agent.device.family or None
        ) if user_agent.device.family != 'Other' else None
        ecs_user_agent.name = user_agent.browser.family or None
        ecs_user_agent.os = OS(
            family=user_agent.os.family,
            version=user_agent.os.version_string or None
        ) if user_agent.os.family != 'Other' else None
        ecs_user_agent.version = user_agent.browser.version_string or None

    return ecs_user_agent


def entry_from_http_message(
    http_message: HTTPMessage,
    include_decompressed_body: bool = False,
    use_host_header: bool = False,
    use_forwarded_header: bool = False,
    public_suffix_list_trie: PublicSuffixListTrie | None = None,
    body_limit: int | None = 4096
) -> Base:
    """
    Produce an entry from an HTTP message.

    :param http_message: An HTTP message from which to produce an entry.
    :param include_decompressed_body: Whether to include a decompressed version of the body.
    :param use_forwarded_header: Whether to parse the `Forwarded` HTTP header.
    :param use_host_header: Whether to parse the `Host` HTTP header.
    :param public_suffix_list_trie: A Public Suffix List trie with which to obtain extra attributes about an HTTP
        request's path.
    :param body_limit: The maximum number of bytes that can be included in the body, or `None` to not use a limit.
    :return:
    """

    headers: dict[str, list[str]] = defaultdict(list)
    for name, value in http_message.headers:
        headers[name.replace('-', '_').lower()].append(value)
    headers = dict(headers)

    content_type: str | None = None
    encoding: str | None = None
    if media_type := parse_content_type(content_type_value=next(iter(headers.get('content_type', [])), '')):
        content_type = media_type.full_type
        encoding = next((value.lower() for (key, value) in media_type.parameters if key.lower() == 'charset'), None)

    decompressed_body: bytes | None = None
    body_mime_type: str | None = None
    include_body = False

    message_bytes = b''

    if http_message.body:
        message_bytes = http_message.body.tobytes()

        body_mime_type: str = magic_from_buffer(buffer=message_bytes, mime=True).lower()
        include_body = (
            body_mime_type not in {'octet-stream', 'application-gzip'}
            and (body_limit is None or len(message_bytes) < body_limit)
        )

        if include_decompressed_body and (decompressed_body := decompress_body(body=message_bytes, mime_type=body_mime_type)):
            decompressed_body_mime_type: str = magic_from_buffer(buffer=decompressed_body, mime=True).lower()
            include_decompressed_body = (
                include_decompressed_body and 'octet-stream' not in decompressed_body_mime_type and (
                    body_limit is None or len(decompressed_body) < body_limit
                )
            )

    network_entry: Network | None = None
    client_entry: Client | None = None
    server_entry: Server | None = None
    destination_entry: Destination | None = None
    url_entry: URL | None = None
    user_agent_entry: ECSUserAgent | None = None

    ecs_http_message_kwargs = dict(
        headers=headers or None,
        body=HttpBody(
            bytes=len(http_message.body) if http_message.body else None,
            content=message_bytes.decode(encoding=encoding or 'charmap') if include_body else None,
            decompressed_content=(
                decompressed_body.decode(encoding=encoding or 'charmap')
                if decompressed_body and include_decompressed_body
                else None
            )
        ),
        bytes=len(http_message.raw) if http_message.raw else None,
        mime_type=body_mime_type or None,
        content_type=content_type
    )

    if isinstance(http_message, HTTPRequest):
        if use_host_header and (host_header_value := next(iter(headers.get('host', [])), None)):
            destination_entry = entry_from_host_header_value(
                host_header_value=host_header_value,
                entry_type=Destination
            )

        if use_forwarded_header and (forwarded_value := next(iter(headers.get('forwarded', [])), None)):
            client_entry, server_entry = entries_from_forwarded_header_value(
                forwarded_header_value=forwarded_value,
                entry_type_for=Client,
                entry_type_host=Server
            )

            if client_entry:
                network_entry = Network(forwarded_ip=client_entry.address)

        if http_message.request_line:
            url_entry = url_entry_from_string(
                url=http_message.request_line.request_target,
                public_suffix_list_trie=public_suffix_list_trie
            )

        user_agent_entry = user_agent_entry_from_string(user_agent_string=next(iter(headers.get('user_agent', [])), ''))

        http_entry = Http(
            request=ECSHttpRequest(
                **ecs_http_message_kwargs,
                method=http_message.request_line.method if http_message.request_line else None,
                referrer=next(iter(headers.get('referer', [])), None),
            ),
            version=(
                (http_message.request_line.http_version or '').removeprefix('HTTP/')
                if http_message.request_line else None
            ) or None
        )
    elif isinstance(http_message, HTTPResponse):
        http_entry = Http(
            response=ECSHttpResponse(
                **ecs_http_message_kwargs,
                status_code=http_message.status_line.status_code if http_message.status_line else None,
                reason_phrase=http_message.status_line.reason_phrase if http_message.status_line else None
            ),
            version=(
                (http_message.status_line.http_version or '').removeprefix('HTTP/')
                if http_message.status_line else None
            ) or None
        )
    else:
        raise ValueError(f'Unexpected HTTP Message type: {http_message}')

    return Base(
        client=client_entry,
        destination=destination_entry,
        http=http_entry,
        network=network_entry,
        server=server_entry,
        url=url_entry,
        user_agent=user_agent_entry
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
        id=errorcode.get(errno_code) if (errno_code := getattr(exception_value, 'errno', None)) is not None else None
    )


def error_from_exception(exception: BaseException) -> Error:
    """
    Produce an ECS `Error` entry from an exception.

    :param exception: An exception from which to produce an `Error` entry.
    :return: An ECS `Error` entry produced from the provided exception.
    """

    return error_entry_from_exc_info(
        exc_info=(type(exception), exception, exception.__traceback__)
    )


def entry_from_log_record(record: LogRecord, field_names: Sequence[str] | None = None) -> Base:
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


def email_bodies_from_email_message(email_message: EmailMessage) -> list[EmailBody]:
    """
    Produce a list of EmailBody entries from an email entries.

    Note that `EmailBody` is a custom field, not part of ECS.

    :param email_message: An email message from which to parse bodies.
    :return: A list of bodies parsed from the email message.
    """

    email_body_list: list[EmailBody] = []

    part: EmailMessage
    for part in email_message.walk():
        if part.get_filename() or part.is_multipart():
            continue

        if part.get_content_maintype() == 'text':
            content = part.get_payload(decode=True)
            email_body_list.append(
                EmailBody(
                    content_type=part.get_content_type(),
                    content=content.decode(encoding='charmap'),
                    size=len(content)
                )
            )

    return email_body_list


def email_file_attachments_from_email_message(email_message: EmailMessage) -> list[EmailAttachmentFile]:
    """
    Produce a list of ECS EmailAttachmentFile entries from an email message.

    :param email_message: An email message from which to parse file attachments.
    :return: A list of file attachments parsed from the email message.
    """

    attachment_file_list: list[EmailAttachmentFile] = []

    part: EmailMessage
    for part in email_message.iter_attachments():
        filename: str | None = part.get_filename()
        file_extension: str | None = None
        if filename:
            file_extension = PurePath(filename).suffix[1:]

        data: bytes | None = part.get_payload(decode=True)
        file_hash = Hash()
        file_len: int | None = None
        if data:
            file_hash.md5 = md5(data).hexdigest()
            file_hash.sha1 = sha1(data).hexdigest()
            file_hash.sha256 = sha256(data).hexdigest()
            file_len = len(data)

        attachment_file_list.append(
            EmailAttachmentFile(
                extension=file_extension,
                hash=file_hash,
                mime_type=part.get_content_type(),
                name=filename,
                size=file_len
            )
        )

    return attachment_file_list


def json_dumps_default(obj: Any):
    if isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, bytes):
        return obj.decode()
    elif isinstance(obj, memoryview):
        return obj.tobytes().decode()

    raise TypeError(f'Unexpected dumps type: {type(obj)}')


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
    generate_field_names: Sequence[str] | None = None,
    provider_name: str | None = None,
    main_dataset_fallback: str | None = None,
    signing_information: SigningInformation | None = None
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

            return json_dumps(obj=log_entry_dict, sort_keys=True, default=json_dumps_default)

        def _get_sequence_number(self) -> int:
            """Claim a sequence number and increment."""
            sequence_number = self._sequence_number
            self._sequence_number += 1
            return sequence_number

        def _emit_signing_error_message(self, record_name: str, exception: BaseException) -> None:
            frameinfo = getframeinfo(currentframe())

            super().emit(
                record=LogRecord(
                    name=record_name,
                    level=ERROR,
                    pathname=frameinfo.filename,
                    lineno=frameinfo.lineno,
                    msg=json_dumps(
                        obj=Base(
                            error=error_from_exception(exception=exception),
                            message='An error occurred when attempting to sign a log record message.',
                            log=Log(logger=self.logger),
                            event=Event(
                                provider=provider_name,
                                dataset='ecs_tools_py',
                                sequence=self._get_sequence_number()
                            )
                        ).to_dict(),
                        sort_keys=True,
                        default=json_dumps_default
                    ),
                    func=frameinfo.function,
                    args=None,
                    exc_info=None
                )
            )

        def _emit_generate_fields_error_message(self, record_name: str, exception: BaseException) -> None:
            frameinfo = getframeinfo(currentframe())

            log_entry_dict: dict[str, Any] = Base(
                error=error_from_exception(exception=exception),
                message='An error occurred when generating fields for a log record.',
                log=Log(logger=self.logger),
                event=Event(
                    provider=provider_name,
                    dataset='ecs_tools_py',
                    sequence=self._get_sequence_number()
                )
            ).to_dict()

            message: str = json_dumps(obj=log_entry_dict, sort_keys=True, default=json_dumps_default)

            if signing_information is not None:
                try:
                    message: str = self._sign(message=message, log_entry_dict=log_entry_dict)
                except BaseException as e:
                    self._emit_signing_error_message(record_name=record_name, exception=e)

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
            except BaseException as e:
                self._emit_generate_fields_error_message(record_name=record.name, exception=e)
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

                extra_dict: dict[str, Any] = {key: record.__dict__[key] for key in extra_keys}

                # (ECS Logger Handler options that can be passed in `extra`.)
                merge_extra = False

                try:
                    options: dict[str, Any] = extra_dict.pop('_ecs_logger_handler_options')
                    merge_extra = bool(options.get('merge_extra'))
                except KeyError:
                    pass

                if merge_extra:
                    log_entry_dict = merge_dict_entries(log_entry_dict, extra_dict)
                else:
                    log_entry_dict[extra_data_namespace_name] = extra_dict

            # Create the JSON-string representation of the log record's dictionary, which constitutes the log message.

            message: str = json_dumps(obj=log_entry_dict, sort_keys=True, default=json_dumps_default)

            # Sign the message if signing information has been provided

            if signing_information is not None:
                try:
                    message: str = self._sign(message=message, log_entry_dict=log_entry_dict)
                except BaseException as e:
                    self._emit_signing_error_message(record_name=record.name, exception=e)

            record.msg = message

            # Clear the record of exception information, which has already been handled, that would confuse the parent
            # `emit` method.

            record.exc_info = None
            record.exc_text = None
            record.stack_info = None

            super().emit(record=record)

    return ECSLoggerHandler
