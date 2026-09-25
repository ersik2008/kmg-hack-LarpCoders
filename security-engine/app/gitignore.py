import os
import re
from typing import List, Tuple

try:
    import pathspec
    HAS_PATHSPEC = True
except ImportError:
    HAS_PATHSPEC = False


class GitIgnoreMatcher:
    def __init__(self, repo_path: str):
        self.repo_path = os.path.abspath(repo_path)
        self.specs: List[Tuple[str, any]] = []  # pathspec specs if available
        self.fallback_rules: List[Tuple[str, str, bool, re.Pattern]] = []
        self._load_all_gitignores()

    def _load_all_gitignores(self):
        ignored_dirs = {
            '.git', 'node_modules', 'dist', 'build', '.next', 'coverage',
            '.cache', 'vendor', '__pycache__', '.idea', '.vscode', '.venv', 'venv'
        }
        for dirpath, dirnames, filenames in os.walk(self.repo_path):
            dirnames[:] = [d for d in dirnames if d not in ignored_dirs]
            if '.gitignore' in filenames:
                gitignore_path = os.path.join(dirpath, '.gitignore')
                rel_dir = os.path.relpath(dirpath, self.repo_path).replace('\\', '/')
                if rel_dir == '.':
                    rel_dir = ''
                try:
                    with open(gitignore_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()

                    if HAS_PATHSPEC:
                        spec = pathspec.GitIgnoreSpec.from_lines(lines)
                        self.specs.append((rel_dir, spec))
                    else:
                        for line in lines:
                            line = line.rstrip('\r\n')
                            if not line or line.startswith('#'):
                                continue
                            self._add_fallback_rule(rel_dir, line)
                except Exception:
                    pass

    def _add_fallback_rule(self, base_rel_dir: str, pattern: str):
        is_negation = False
        if pattern.startswith('!'):
            is_negation = True
            pattern = pattern[1:]

        pattern = pattern.strip()
        if not pattern:
            return

        regex = self._pattern_to_regex(pattern)
        if regex:
            self.fallback_rules.append((base_rel_dir, pattern, is_negation, regex))

    def _pattern_to_regex(self, pattern: str) -> re.Pattern:
        is_dir_only = pattern.endswith('/')
        if is_dir_only:
            pattern = pattern[:-1]

        anchored = pattern.startswith('/')
        if anchored:
            pattern = pattern[1:]

        res = []
        i = 0
        n = len(pattern)
        while i < n:
            c = pattern[i]
            if c == '*':
                if i + 1 < n and pattern[i + 1] == '*':
                    if i + 2 < n and pattern[i + 2] == '/':
                        res.append('(?:.*/)?')
                        i += 3
                    else:
                        res.append('.*')
                        i += 2
                else:
                    res.append('[^/]*')
                    i += 1
            elif c == '?':
                res.append('[^/]')
                i += 1
            elif c in '.+^$()[]{}|\\':
                res.append('\\' + c)
                i += 1
            else:
                res.append(c)
                i += 1

        pattern_regex = ''.join(res)
        if not anchored and '/' not in pattern:
            regex_str = r'(?:^|/)' + pattern_regex + r'(?:/.*|$)'
        else:
            regex_str = r'^' + pattern_regex + r'(?:/.*|$)'

        try:
            return re.compile(regex_str)
        except Exception:
            return None

    def is_ignored(self, path: str) -> bool:
        if not path or path == '.':
            return False

        if os.path.isabs(path):
            rel_path = os.path.relpath(path, self.repo_path).replace('\\', '/')
        else:
            rel_path = path.replace('\\', '/')

        rel_path = rel_path.strip('/')
        if not rel_path or rel_path == '.':
            return False

        if HAS_PATHSPEC:
            for rel_dir, spec in self.specs:
                if rel_dir:
                    if rel_path.startswith(rel_dir + '/') or rel_path == rel_dir:
                        sub_path = rel_path[len(rel_dir) + 1:] if rel_path.startswith(rel_dir + '/') else rel_path
                        if spec.match_file(sub_path):
                            return True
                else:
                    if spec.match_file(rel_path):
                        return True
            return False
        else:
            ignored = False
            for base_dir, pattern_str, is_negation, regex in self.fallback_rules:
                if base_dir:
                    if not (rel_path.startswith(base_dir + '/') or rel_path == base_dir):
                        continue
                    check_path = rel_path[len(base_dir) + 1:] if rel_path.startswith(base_dir + '/') else rel_path
                else:
                    check_path = rel_path

                if regex.search(check_path):
                    ignored = not is_negation
            return ignored
