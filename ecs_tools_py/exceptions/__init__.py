class UnexpectedFieldsError(Exception):
    def __init__(self, unsupported_fields: set[str]):
        super().__init__(f'Unsupported fields: {list(unsupported_fields)}')
        self.unsupported_fields = unsupported_fields


class NamespaceFieldIsNotDataclassError(Exception):
    def __init__(self, field: str):
        super().__init__(f'Namespace field is not a dataclass: {field}')
        self.field = field


class UnhandledDerivedFieldError(Exception):
    def __init__(self, field: str):
        super().__init__(f'Unhandled derived field: {field}')
        self.field = field
