#!/usr/bin/env python3
"""Repackage ONLY the current user's existing paired compatibility runtime.
No new application identity, keys, TLS policy or native-product gate is created.
"""
import argparse
import hashlib
import ipaddress
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def owned(path):
    if not path.is_absolute() or path != Path(os.path.normpath(path)):
        raise ValueError('Expected a canonical local path.')
    for part in [path, *path.parents]:
        if part.is_symlink():
            raise ValueError('Linked personal installation paths are not supported.')
        if part.exists() and part.stat().st_mode & 0o022:
            raise ValueError('Personal installation paths may not be writable by other users.')
    if not path.is_file() or path.stat().st_uid != os.getuid() or path.stat().st_nlink != 1:
        raise ValueError('Expected an owned regular paired file.')


def validate_pair(home):
    agent = home / '.local/libexec/lanpilot-tls/rwn-desktop-agent'
    service = home / 'Library/LaunchAgents/com.lanpilot.desktop-tls.plist'
    owned(agent); owned(service)
    if not os.access(agent, os.X_OK) or service.stat().st_size > 65536:
        raise ValueError('Existing personal runtime/service is invalid.')
    if (home / 'Applications/LanPilot.app').exists() or (home / 'Applications/LanPilot.app').is_symlink():
        raise ValueError('Use the native application owner, not this compatibility package.')
    data = plistlib.loads(service.read_bytes())
    allowed = {'Label','ProgramArguments','LimitLoadToSessionType','RunAtLoad','KeepAlive',
               'ThrottleInterval','Umask','WorkingDirectory','StandardOutPath','StandardErrorPath'}
    if set(data) != allowed:
        raise ValueError('Unexpected existing service fields.')
    expected = dict(Label='com.lanpilot.desktop-tls', LimitLoadToSessionType='Aqua',
                    RunAtLoad=True, KeepAlive=True, ThrottleInterval=10, Umask=63,
                    WorkingDirectory=str(home), StandardOutPath='/dev/null')
    if any(data.get(k) != v for k, v in expected.items()):
        raise ValueError('Existing service policy does not match the approved compatibility path.')
    args = data['ProgramArguments']
    if (not isinstance(args, list) or len(args) not in (10,11) or
            not all(isinstance(x,str) and '\n' not in x and '\r' not in x for x in args) or
            args[0] != str(agent) or args[1] != '--stream-visual-tls' or
            args[7] not in ['interactive','view-only'] or args[8] not in ['exact-only','h264-only'] or
            (len(args)==11 and (args[10]!='--clipboard-text' or args[7]!='interactive'))):
        raise ValueError('Unsupported existing stream policy.')
    address = ipaddress.ip_address(args[2])
    if address.version != 4 or not address.is_private or address.is_unspecified or address.is_multicast:
        raise ValueError('Existing service must use an explicit private IPv4 endpoint.')
    if not args[3].isdigit() or not 1024 <= int(args[3]) <= 65535:
        raise ValueError('Unexpected existing endpoint port.')
    if not re.fullmatch(r'[0-9a-fA-F]{2,8192}', args[4]) or not re.fullmatch(r'[0-9a-fA-F]{64}',args[5]):
        raise ValueError('Invalid existing protected identity reference.')
    for index in [6,9]:
        trust = Path(args[index]); owned(trust)
        if not str(trust).startswith(str(home / '.local/share/lanpilot/identity-v1')+'/') or trust.stat().st_size > 65536:
            raise ValueError('Unexpected existing trust resource.')
    if data['StandardErrorPath'] not in ['/dev/null',str(home / '.local/share/lanpilot/logs/clipboard-startup.log')]:
        raise ValueError('Unexpected existing diagnostics path.')
    return agent, service, dict(agent_sha256=digest(agent),service_sha256=digest(service))


def run(*args):
    subprocess.run([str(x) for x in args],check=True,timeout=120)


def write_presentation(work):
    """Static, offline Installer pages; never include machine/profile data."""
    resources = work / 'resources'
    resources.mkdir(exist_ok=True)
    here = Path(__file__).resolve().parent
    for name in ['welcome.html', 'conclusion.html']:
        shutil.copyfile(here / 'personal-resources' / name, resources / name)
    xml = '''<?xml version="1.0" encoding="UTF-8"?>
<installer-gui-script minSpecVersion="2">
 <title>LanPilot</title>
 <options customize="never" require-scripts="true" allow-external-scripts="false"/>
 <domains enable_anywhere="false" enable_currentUserHome="true" enable_localSystem="false"/>
 <welcome file="welcome.html" mime-type="text/html"/>
 <conclusion file="conclusion.html" mime-type="text/html"/>
 <choices-outline><line choice="personal"/></choices-outline>
 <choice id="personal" visible="false"><pkg-ref id="com.lanpilot.personal.compatibility"/></choice>
 <pkg-ref id="com.lanpilot.personal.compatibility" version="1.0" auth="none">LanPilot-personal-component.pkg</pkg-ref>
</installer-gui-script>
'''
    (work / 'Distribution.xml').write_text(xml, encoding='utf-8')
    return resources


def assemble(home, output, license_path):
    agent, service, contract = validate_pair(home)
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise ValueError('Personal package output must be create-new.')
    before = (digest(agent),digest(service))
    here = Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory(prefix='lanpilot-personal-pkg-',dir=output.parent) as temporary:
        work = Path(temporary); root = work/'root'; scripts = work/'scripts'; resources=work/'resources'
        root.mkdir(); scripts.mkdir(); resources.mkdir()
        relative = Path('.local/libexec/lanpilot-tls')
        target = root/relative
        target.mkdir(parents=True)
        # Preserve the real installation's directory modes; do not broaden them.
        for part in [Path('.local'),Path('.local/libexec'),relative]:
            (root/part).chmod((home/part).stat().st_mode & 0o777)
        shutil.copyfile(agent,target/'rwn-desktop-agent')
        (target/'rwn-desktop-agent').chmod(agent.stat().st_mode & 0o777)
        shutil.copyfile(license_path,target/'LICENSE.txt')
        (target/'LICENSE.txt').chmod(0o644)
        shutil.copyfile(here/'personal-runtime-check.sh',scripts/'personal-runtime-check.sh')
        with (scripts/'contract.plist').open('wb') as stream:
            plistlib.dump(contract,stream)
        header='#!/bin/sh\nset -eu\npersonal_scripts=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\n. "$personal_scripts/personal-runtime-check.sh"\npersonal_context\n'
        (scripts/'preinstall').write_text(header+'personal_check "$personal_home" "$personal_uid" "$personal_scripts/contract.plist" preinstall\n')
        post=header+'personal_check "$personal_home" "$personal_uid" "$personal_scripts/contract.plist" postinstall\n'
        post+='''personal_job="gui/$personal_uid/com.lanpilot.desktop-tls"
if ! /bin/launchctl print "$personal_job" >/dev/null 2>&1; then
    /bin/launchctl bootstrap "gui/$personal_uid" "$personal_plist"
fi
# No -k: never terminate an existing connection. Only start the existing owner.
/bin/launchctl kickstart "$personal_job"
printf '%s\\n' 'LanPilot personal runtime ready; existing pairing retained.'
'''
        (scripts/'postinstall').write_text(post)
        for name in ['preinstall','postinstall','personal-runtime-check.sh']:
            (scripts/name).chmod(0o755)
        write_presentation(work)
        run('/usr/bin/pkgbuild','--root',root,'--scripts',scripts,'--identifier','com.lanpilot.personal.compatibility',
            '--version','1.0','--install-location','/','--ownership','recommended',work/'LanPilot-personal-component.pkg')
        run('/usr/bin/productbuild','--distribution',work/'Distribution.xml','--resources',resources,'--package-path',work,work/'result.pkg')
        if before != (digest(agent),digest(service)):
            raise ValueError('The installed runtime/service changed while packaging; no package published.')
        os.link(work/'result.pkg',output)
    return contract


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True)
    parser.add_argument('--license',required=True)
    args=parser.parse_args()
    try:
        if sys.platform!='darwin' or os.getuid()==0:
            raise ValueError('Build on this paired Mac as its normal user.')
        output=Path(args.output)
        if not output.is_absolute() or output.name!='LanPilot-Mac-Personal.pkg':
            raise ValueError('Expected an absolute LanPilot-Mac-Personal.pkg output.')
        contract=assemble(Path.home(),output,Path(args.license))
        print('personal_installer=BUILT runtime='+contract['agent_sha256']+' keys_copied=0 settings_copied=0 installed=0')
    except (ValueError,OSError,subprocess.SubprocessError) as error:
        parser.exit(1,f'personal_installer=REJECTED reason={error}\n')


if __name__=='__main__':
    main()
