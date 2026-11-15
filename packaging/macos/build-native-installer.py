#!/usr/bin/env python3
"""Maintainer-only packaging. Never install, sign ad-hoc, grant or start services."""
import argparse
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
from xml.sax.saxutils import escape


def run(*args):
    subprocess.run([str(x) for x in args], check=True, timeout=120)


def regular_ancestry(path):
    if not path.is_absolute() or path != Path(os.path.normpath(path)):
        raise ValueError('An absolute canonical path is required.')
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('Linked packaging paths are not accepted.')


def inventory(app):
    regular_ancestry(app)
    if not app.is_dir() or app.name != 'LanPilot.app':
        raise ValueError('Expected the staged LanPilot.app bundle.')
    entries = sorted(app.rglob('*'))
    total = 0
    for p in [app, *entries]:
        if p.is_symlink() or not (p.is_dir() or p.is_file()):
            raise ValueError('Unexpected linked/special application member.')
        if p.stat().st_mode & 0o022:
            raise ValueError('Application members must not be writable by other users.')
        if p.is_file():
            size = p.stat().st_size
            total += size
            if size > 256 * 1024**2 or total > 512 * 1024**2:
                raise ValueError('Application exceeds package limits.')
    if len(entries) > 4096:
        raise ValueError('Application member limit exceeded.')
    with (app / 'Contents/Info.plist').open('rb') as f:
        info = plistlib.load(f)
    if (info.get('CFBundleIdentifier') != 'com.lanpilot.desktop' or
            info.get('CFBundleExecutable') != 'LanPilot' or
            info.get('CFBundlePackageType') != 'APPL' or
            info.get('LSMinimumSystemVersion') != '13.0' or
            not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', info.get('CFBundleVersion', ''))):
        raise ValueError('Unexpected application identity/version contract.')
    executable = app / 'Contents/MacOS/LanPilot'
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise ValueError('Missing application executable.')
    return info['CFBundleVersion']


def build(args):
    if sys.platform != 'darwin':
        raise ValueError('Build this native package on macOS.')
    app, output = Path(args.app), Path(args.output)
    regular_ancestry(output.parent)
    if not output.parent.is_dir() or output.exists() or output.is_symlink():
        raise ValueError('Output must be a new file in an existing directory.')
    version = inventory(app)
    if args.mode == 'release':
        if (not re.fullmatch(r'[A-Z0-9]{10}', args.team or '') or
                not re.fullmatch(r'[0-9a-f]{128}', args.release_key or '') or
                args.release_key == '0' * 128 or
                not re.fullmatch(r'[0-9A-Fa-f]{40}', args.installer_identity or '')):
            raise ValueError('Release requires the configured publisher team, pinned release key and Developer ID Installer identity.')
        requirement = ('anchor apple generic and identifier "com.lanpilot.desktop" '
                       f'and certificate leaf[subject.OU] = "{args.team}" '
                       'and certificate leaf[field.1.2.840.113635.100.6.1.13] exists')
        run('/usr/bin/codesign', '--verify', '--deep', '--strict', '--all-architectures', '-R', requirement, app)
        run('/usr/sbin/spctl', '--assess', '--type', 'execute', app)
        if output.name != 'LanPilot-macOS.pkg':
            raise ValueError('Release filename must be LanPilot-macOS.pkg.')
    elif not output.name.endswith('-UNSIGNED.pkg'):
        raise ValueError('Development packages must end in -UNSIGNED.pkg.')
    arches = subprocess.check_output(['/usr/bin/lipo', '-archs', str(app / 'Contents/MacOS/LanPilot')], text=True).split()
    if set(arches) != {'arm64', 'x86_64'}:
        raise ValueError('The installer requires the universal2 application.')
    here = Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory(prefix='lanpilot-pkg-', dir=output.parent) as temporary:
        work = Path(temporary)
        root, scripts, resources = work / 'root', work / 'scripts', work / 'resources'
        (root / 'Applications').mkdir(parents=True)
        scripts.mkdir(); resources.mkdir()
        run('/usr/bin/ditto', app, root / 'Applications/LanPilot.app')
        shutil.copyfile(here / 'installer-preinstall.sh', scripts / 'preinstall')
        (scripts / 'preinstall').chmod(0o755)
        component = [dict(RootRelativeBundlePath='Applications/LanPilot.app',
                          BundleIsRelocatable=False, BundleIsVersionChecked=True,
                          BundleHasStrictIdentifier=True, BundleOverwriteAction='upgrade')]
        with (work / 'components.plist').open('wb') as f:
            plistlib.dump(component, f)
        title = 'LanPilot' if args.mode == 'release' else 'LanPilot — unsigned development package'
        welcome = ('Install LanPilot for this Mac account. No Terminal commands, certificates or private-key files are needed.\n\n'
                   'This places only LanPilot.app in your home Applications folder. Saved settings, keys, permissions and existing services are untouched.\n\n'
                   'This is a first-install package. Existing canonical installations must use the verified in-app updater.\n')
        if args.mode != 'release':
            welcome += '\nDEVELOPMENT ONLY: publisher signing and notarization are incomplete. Installation cannot make this build eligible for production activation.\n'
        (resources / 'welcome.txt').write_text(welcome)
        (resources / 'conclusion.txt').write_text(
            'Open LanPilot from your home Applications folder. Complete the first-use pairing and macOS privacy permissions in the app.\n\n'
            'No service, remote control, clipboard sync or private key was activated by this installer.\n')
        xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<installer-gui-script minSpecVersion="2">
 <title>{escape(title)}</title>
 <options customize="never" require-scripts="true" allow-external-scripts="false" hostArchitectures="arm64,x86_64"/>
 <domains enable_anywhere="false" enable_currentUserHome="true" enable_localSystem="false"/>
 <volume-check><allowed-os-versions><os-version min="13.0"/></allowed-os-versions></volume-check>
 <welcome file="welcome.txt" mime-type="text/plain"/>
 <conclusion file="conclusion.txt" mime-type="text/plain"/>
 <choices-outline><line choice="lanpilot"/></choices-outline>
 <choice id="lanpilot" visible="false"><pkg-ref id="com.lanpilot.desktop.pkg"/></choice>
 <pkg-ref id="com.lanpilot.desktop.pkg" version="{version}" auth="none">LanPilot-component.pkg</pkg-ref>
</installer-gui-script>
'''
        (work / 'Distribution.xml').write_text(xml)
        run('/usr/bin/pkgbuild', '--root', root, '--component-plist', work / 'components.plist',
            '--scripts', scripts, '--identifier', 'com.lanpilot.desktop.pkg', '--version', version,
            '--install-location', '/', '--ownership', 'recommended', work / 'LanPilot-component.pkg')
        command = ['/usr/bin/productbuild', '--distribution', work / 'Distribution.xml',
                   '--resources', resources, '--package-path', work]
        if args.mode == 'release':
            command += ['--sign', args.installer_identity]
        run(*command, work / 'result.pkg')
        if args.mode == 'release':
            run('/usr/sbin/pkgutil', '--check-signature', work / 'result.pkg')
        # Hard-link publication is create-new and cannot silently overwrite.
        os.link(work / 'result.pkg', output)
    print(f'macos_installer=BUILT mode={args.mode} installed=0 services_started=0 trust_changed=0')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--mode', choices=['development', 'release'], default='development')
    parser.add_argument('--team')
    parser.add_argument('--release-key')
    parser.add_argument('--installer-identity')
    args = parser.parse_args()
    try:
        build(args)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, f'macos_installer=REJECTED reason={error}\n')


if __name__ == '__main__':
    main()
