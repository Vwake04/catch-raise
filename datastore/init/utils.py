import time
from contextlib import contextmanager

import click


def info(msg, nl=True):
    click.echo("[*] {}".format(msg), nl=nl)


def error(msg, nl=True):
    click.echo("[error] {}".format(msg), nl=nl)


def header(msg):
    click.echo("#" * len(msg))
    click.echo(msg)
    click.echo("#" * len(msg))


@contextmanager
def timed_operation(msg, nl=False):
    start = time.time()
    info(msg, nl=nl)
    yield
    click.echo(" (done in {}s).".format(round(time.time() - start, 3)))

