#!/usr/bin/env python2

import re
import sys

def gen_embedded(content):
    content = re.sub(r'{{.*?}}', '%s', re.sub(r'{%.*?%}', '', content))
    part_headers = list(re.finditer(r'<!-- part (\S+) -->', content))
    if not part_headers:
        print('Error: no parts found')
        return

    def process_part(part):
        return "\n".join(
            "\"" + line.lstrip().replace('"', '\\"') + "\""
            for line in part.split("\n")
            if line.strip()
        )

    result = ''

    for p1, p2 in zip(part_headers, part_headers[1:]):
        result += "const char *%s = \n%s;\n\n" % (
            p1.group(1).lower(),
            process_part(content[p1.end():p2.start()])
        )

    result += "const char *%s = \n%s;" % (
        part_headers[-1].group(1).lower(),
        process_part(content[part_headers[-1].end():])
    )

    return result


def main():
    file_path = sys.argv[1]
    vars = {}
    with open("header.h") as f:
        for cnt, line in enumerate(f):
            p = line.rstrip().split(" ")
            if (p[0] == '#define'):
                v = p[-1]
                if (v[0] == '"' and v[-1] == '"'):
                    v = v[1:-1]
                vars['DEF_' + p[1]] = v
    with open(file_path) as f:
        content = f.read().replace('{', '{{').replace('}', '}}').replace('[[[', '{').replace(']]]', '}')
        print(gen_embedded(content.format(**vars)))


if __name__ == '__main__':
    main()
