#! /usr/bin/env python
from datetime import datetime
import re
import sys

log_mask = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \+\d{4}, (?:([^:]+):\d+), ([a-z]+) ([^ ]+) ([0-9]+)( .*)?$"
)

def parse_file(fname):
    with open(fname) as infile:
        for line in infile:
            match = log_mask.match(line)
            if match:
                date_ = match.group(1)
                cnc = match.group(2)
                cmd = match.group(3)
                targets_ = match.group(4)
                duration_ = match.group(5)
                options_ = match.group(6)

                targets = targets_.split(',')
                date = datetime.strptime(date_, '%Y-%m-%d %H:%M:%S')
                duration = int(duration_)
                options = {}
                if options_ != '':
                    for opt in options_.split(' '):
                        data = opt.split('=')
                        key = data[0]
                        value = ''.join(data[1:])
                        options[key] = value

                yield date, cnc, cmd, targets, duration, options

if __name__ == '__main__':
    for date, cnc, cmds, targets, duration, options in parse_file(sys.argv[1]):
        print date, cnc, cmds, targets, duration, options
