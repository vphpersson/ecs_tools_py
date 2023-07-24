#!/usr/bin/env python

from argparse import ArgumentParser, FileType
from sys import stdin
from email import message_from_binary_file

from ecs_py import Base
from ecs_tools_py import email_from_email_message, related_from_ecs_email, make_log_action, LOG


class ECSFromEmailAngumentParser(ArgumentParser):
    def __init__(self, *args, **kwargs):
        super().__init__(
            *args,
            **(
                dict(
                    description='Make an ECS email entry from an email.'
                ) | kwargs
            )
        )

        self.add_argument(
            '--path',
            type=FileType('rb'),
            default=stdin,
            help='A path to a file from which to read an email. Defaults to stdin.',
        )

        self.add_argument(
            '--log',
            action=make_log_action(event_provider='ecs_from_email', log=LOG)
        )


def main():
    try:
        args = ECSFromEmailAngumentParser().parse_args()

        try:
            ecs_email = email_from_email_message(
                email_message=message_from_binary_file(fp=args.path),
                include_raw_headers=True,
                extract_attachments=True,
                extract_bodies=True,
                extract_attachment_contents=False,
                extract_body_content=True
            )

            if bodies := ecs_email.bodies:
                if any(body.content_type == 'text/plain' for body in bodies):
                    for body in bodies:
                        if body.content_type != 'text/plain':
                            body.content = None

            base = Base(email=ecs_email, related=related_from_ecs_email(ecs_email=ecs_email))
        except KeyboardInterrupt:
            return
        except Exception:
            LOG.exception(
                msg='An unexpected error occurred when parsing an email.',
                extra=dict(
                    error=dict(input=str(args.path)),
                    _ecs_logger_handler_options=dict(merge_extra=True)
                )
            )
            exit(1)
        else:
            print(base)
    except KeyboardInterrupt:
        pass
    except Exception:
        LOG.exception(msg='An unexpected exception occurred.')
        exit(1)


if __name__ == '__main__':
    main()
