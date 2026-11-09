# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
import hashlib
import json
import re

def sha(b):
    return hashlib.sha256(b).hexdigest()

def tokens(text):
    text = re.sub('/\\*.*?\\*/|//[^\\n]*', '', text, flags=re.S)
    pattern = "\\d+'[sS]?[bBoOdDhH][0-9a-fA-F_xXzZ]+|\\d+|[A-Za-z_$][\\w$]*(?:\\.[A-Za-z_$][\\w$]*)*|==|!=|<=|>=|&&|\\|\\||<<|>>|[.{}()\\[\\],;:#@?=+*/%&|^~!<>-]"
    result = re.findall(pattern, text)
    if not not re.sub(pattern, '', text).strip():
        raise ValueError('Unsupported source token')
    return result

def matching(ts, start):
    if not ts[start] == '(':
        raise ValueError('Trace contract failed')
    depth = 1
    pos = start + 1
    while depth:
        if ts[pos] == '(':
            depth += 1
        if ts[pos] == ')':
            depth -= 1
        pos += 1
    return pos

def properties(source):
    source = re.sub(r'/\*.*?\*/|//[^\n]*', '', source, flags=re.S)
    ts = tokens(re.sub('\\bfunction\\b.*?\\bendfunction\\b', '', source, flags=re.S))
    found = {}

    def statement(pos, guards, clock):
        if ts[pos] == 'begin':
            pos += 1
            while ts[pos] != 'end':
                pos = statement(pos, guards, clock)
            return pos + 1
        if ts[pos] == 'if':
            end = matching(ts, pos + 1)
            condition = ts[pos + 2:end - 1]
            pos = statement(end, guards + [(condition, True)], clock)
            if ts[pos] == 'else':
                pos = statement(pos + 1, guards + [(condition, False)], clock)
            return pos
        if ts[pos + 1:pos + 3] in ([':', 'assert'], [':', 'assume'], [':', 'cover']):
            label, kind = (ts[pos], ts[pos + 2])
            end = matching(ts, pos + 3)
            if not (ts[end] == ';' and label not in found):
                raise ValueError('Trace contract failed')
            found[label] = {'kind': kind, 'body': ts[pos + 4:end - 1], 'guards': [{'tokens': g, 'positive': p} for g, p in guards], 'clock': clock}
            return end + 1
        depth = 0
        while not (ts[pos] == ';' and depth == 0):
            if ts[pos] in ('(', '[', '{'):
                depth += 1
            if ts[pos] in (')', ']', '}'):
                depth -= 1
            pos += 1
        return pos + 1
    pos = 0
    while pos < len(ts):
        if ts[pos] == 'always':
            if not ts[pos + 1:pos + 3] == ['@', '(']:
                raise ValueError('Trace contract failed')
            end = matching(ts, pos + 2)
            pos = statement(end, [], ts[pos + 3:end - 1])
        else:
            pos += 1
    return found

def check_property(allprops, label, kind, guards, body):
    r = allprops[label]
    if not (r['kind'] == kind and r['clock'] == tokens('posedge clock')):
        raise ValueError(label)
    if not r['guards'] == [{'tokens': tokens(g), 'positive': True} for g in guards]:
        raise ValueError(label)
    if not r['body'] == tokens(body):
        raise ValueError(label)
    return {'sourceProperty': label, 'kind': kind, 'clock': 'posedge clock', 'guardConjuncts': guards, 'body': body, 'sourcePropertyTokensSha256': sha(json.dumps(r, sort_keys=True).encode())}
