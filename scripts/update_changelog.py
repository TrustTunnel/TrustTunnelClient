#!/usr/bin/env python3
"""
Update CHANGELOG.md for a new release:
1. Replace [Unreleased] with new version and date
2. Remove empty sections from the released version
3. Add fresh [Unreleased] section with all subsections
"""
import sys


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <new_version> <date>", file=sys.stderr)
        print(f"Example: {sys.argv[0]} 1.2.3 2026-05-13", file=sys.stderr)
        sys.exit(1)

    new_version = sys.argv[1]
    today = sys.argv[2]

    with open('CHANGELOG.md', 'r') as f:
        content = f.read()

    lines = content.split('\n')
    result = []
    i = 0

    while i < len(lines):
        line = lines[i]

        # Found the Unreleased section
        if line.strip() == '## [Unreleased]':
            # Add new Unreleased section
            result.append('## [Unreleased]')
            result.append('')
            result.append('### Added')
            result.append('')
            result.append('### Changed')
            result.append('')
            result.append('### Removed')
            result.append('')

            # Add the new version header
            result.append(f'## [{new_version}] - {today}')
            i += 1

            # Process the old Unreleased content until next ## section
            section_content = {}
            current_section = None

            while i < len(lines) and not lines[i].startswith('## ['):
                line = lines[i]
                if line.startswith('### '):
                    current_section = line
                    section_content[current_section] = []
                elif current_section and line.strip():
                    section_content[current_section].append(line)
                i += 1

            # Output non-empty sections
            for section, items in section_content.items():
                if items:  # Only include sections with content
                    result.append('')
                    result.append(section)
                    result.append('')
                    for item in items:
                        result.append(item)

            result.append('')
            continue

        result.append(line)
        i += 1

    with open('CHANGELOG.md', 'w') as f:
        f.write('\n'.join(result))

    print(f"Updated CHANGELOG.md with version {new_version}")


if __name__ == '__main__':
    main()
