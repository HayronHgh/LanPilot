"""Build/expand an isolated native installer; NEVER install it or launch an app."""
import argparse
import hashlib
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET


def run(*args, success=True):
    result = subprocess.run([str(x) for x in args], capture_output=True, text=True, timeout=90)
    assert (result.returncode == 0) == success, result.stdout + result.stderr
    return result


def tree(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob('*') if p.is_file()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--app', required=True)
    parser.add_argument('--builder', required=True)
    args = parser.parse_args()
    app, builder = Path(args.app), Path(args.builder)
    source = tree(app)
    with tempfile.TemporaryDirectory(prefix='lanpilot-pkg-test-') as temporary:
        root = Path(temporary).resolve()
        package = root / 'LanPilot-macOS-UNSIGNED.pkg'
        run(sys.executable, builder, '--app', app, '--output', package)
        run(sys.executable, builder, '--app', app, '--output', package, success=False)
        run(sys.executable, builder, '--app', app, '--output', root / 'release.pkg', '--mode', 'release', success=False)
        assert not (root / 'release.pkg').exists()
        run('/usr/sbin/pkgutil', '--expand-full', package, root / 'expanded')
        expanded = root / 'expanded'
        distribution = ET.parse(expanded / 'Distribution').getroot()
        domains = distribution.find('domains')
        assert domains is not None and domains.attrib == dict(enable_anywhere='false', enable_currentUserHome='true', enable_localSystem='false')
        assert distribution.find('options').get('allow-external-scripts') == 'false'
        assert distribution.find('pkg-ref').get('auth') == 'none'
        payloads = list(expanded.glob('*.pkg/Payload'))
        assert len(payloads) == 1
        payload = payloads[0]
        assert sorted(p.name for p in payload.iterdir()) == ['Applications']
        assert sorted(p.name for p in (payload / 'Applications').iterdir()) == ['LanPilot.app']
        assert tree(payload / 'Applications/LanPilot.app') == source
        scripts = payload.parent / 'Scripts'
        assert sorted(p.name for p in scripts.iterdir()) == ['preinstall']
        guard = builder.parent / 'installer-preinstall.sh'
        assert (scripts / 'preinstall').read_bytes() == guard.read_bytes()
        assert not list(expanded.rglob('postinstall'))
        info = ET.parse(payload.parent / 'PackageInfo').getroot()
        assert info.get('install-location') == '/'
        assert info.find('bundle').get('path') == './Applications/LanPilot.app'
        assert info.find('bundle-version').find('bundle').get('id') == 'com.lanpilot.desktop'
        # Test the unchanged read-only layout function against private fixtures.
        body = guard.read_text().rsplit('main "$@"', 1)[0]
        home = root / 'fixture home'; home.mkdir()
        script = root / 'guard.sh'; script.write_text(body + '\ncheck_layout "$1" "$2"\n')
        for case in ['fresh', 'existing', 'linked', 'writable', 'regular']:
            apps = home / 'Applications'
            if apps.is_symlink():
                apps.unlink()
            elif apps.exists():
                shutil.rmtree(apps)
            if case == 'existing':
                (apps / 'LanPilot.app').mkdir(parents=True)
            elif case == 'linked':
                apps.symlink_to(root / 'elsewhere')
            elif case in ['writable', 'regular']:
                apps.mkdir()
                apps.chmod(0o777 if case == 'writable' else 0o755)
            run('/bin/sh', script, home, str(os.getuid()), success=case in ['fresh', 'regular'])
        assert tree(app) == source
    print('macos_installer_workflow=PASS expanded_pixels=0 payload_hashes=matched home_only=1 guards=5 release_gate=closed installed=0 listener_started=0')


if __name__ == '__main__':
    main()
