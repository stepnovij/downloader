"""
Download file from url to disk with resume
Inspired by: https://gist.github.com/tobiasraabe/58adee67de619ce621464c1a6511d7d9#file-python-downloader-py
"""
import argparse
import hashlib
from pathlib import Path
import math
import os
import re
import signal

import click
import requests
from tqdm import tqdm


__version__ = '0.1.0'

BLOCK_SIZE = 1024


def convert_size(size_bytes: int) -> str:
    if size_bytes == 0:
        return '0B'
    size_name = ('B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB')
    i = int(math.floor(math.log(size_bytes, BLOCK_SIZE)))
    p = math.pow(BLOCK_SIZE, i)
    s = round(size_bytes / p, 2)
    return '%s %s' % (s, size_name[i])


def get_sha256(path: Path) -> str:
    sha256 = hashlib.sha256(open(str(path.resolve()), 'rb').read()).hexdigest()
    click.echo(f'Compare with the original file using SHA256: {sha256}. It must be the same.')
    return sha256


def validate_path(path_string):
    path = Path(path_string)
    if not path.is_file():
        raise argparse.ArgumentTypeError('Path must be a valid file path (with filename)')
    return path


def validate_url(url_string):
    regex = re.compile(
            r'^(?:http|ftp)s?://' # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
            r'localhost|' #localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
            r'(?::\d+)?' # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    if not re.match(regex, url_string):
        raise argparse.ArgumentTypeError('URL must be a valid url (with http/https/ftp)')
    return url_string


def _download(url: str, path: Path, content_length, resume_byte_pos: int = None):
    resume_header = {'Range': f'bytes={resume_byte_pos}-'} if resume_byte_pos else {}

    r = requests.get(url, stream=True, headers=resume_header)

    initial_pos = resume_byte_pos if resume_byte_pos else 0
    mode = 'ab' if resume_byte_pos else 'wb'

    with open(str(path.resolve()), mode) as f:
        with tqdm(total=content_length,
                  unit='B',
                  unit_scale=True,
                  unit_divisor=BLOCK_SIZE,
                  desc=path.name,
                  initial=initial_pos,
                  ascii=True,
                  miniters=1) as pbar:
            for chunk in r.iter_content(32 * BLOCK_SIZE):
                f.write(chunk)
                pbar.update(len(chunk))
    click.echo(f'File download completed: {str(path.resolve())} and size on disk {convert_size(path.stat().st_size)}')


def download(url: str, path: Path) -> None:
    r = requests.head(url, allow_redirects=True)
    content_length = int(r.headers.get('content-length', 0))
    click.echo(f'File at url {url} has size of {convert_size(content_length)}')

    if path.exists():
        file_size = path.stat().st_size
        if file_size == content_length:
            click.echo(f'File {str(path.resolve())} is already downloaded!')
            get_sha256(path)
            return
    else:
        click.echo(f'Let\'s create file: {str(path.resolve())}')
        path.touch()
        file_size = path.stat().st_size
    click.echo(f'File size on disk: {convert_size(file_size)}')
    _download(url, path, content_length, resume_byte_pos=file_size)
    get_sha256(path)


def get_parser():
    """Creates a new argument parser."""
    parser = argparse.ArgumentParser(description='Download file in sequential manner from specified url')
    version = '%(prog)s ' + __version__
    parser.add_argument('--version', '-v', action='version', version=version)
    parser.add_argument('--url', dest='url', type=validate_url, required=True, help='url of the file')
    parser.add_argument('--path', dest='path', type=validate_path, required=True, help='path to the file')
    return parser


def receive_signal(sig_num, frame):
    click.echo(f'Received signal: {sig_num}')
    raise SystemExit('Finishing downloading')


def main(args=None):
    signal.signal(signal.SIGINT, receive_signal)
    signal.signal(signal.SIGTERM, receive_signal)
    parser = get_parser()
    args = parser.parse_args(args)
    download(url=args.url, path=args.path)


if __name__ == '__main__':
    main()
