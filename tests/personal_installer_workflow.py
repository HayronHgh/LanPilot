"""Isolated compatibility-package proof. Never execute postinstall or launchd."""
import importlib.util
from html.parser import HTMLParser
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET


def run(*args, success=True):
    result=subprocess.run([str(x) for x in args],capture_output=True,text=True,timeout=90)
    assert (result.returncode==0)==success,result.stdout+result.stderr
    return result


def main():
    builder=Path(sys.argv[1]); license_path=Path(sys.argv[2])
    spec=importlib.util.spec_from_file_location('personal_package',builder)
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    with tempfile.TemporaryDirectory(prefix='lanpilot-personal-test-') as temporary:
        root=Path(temporary).resolve(); fixture=root/'fixture user'; fixture.mkdir(mode=0o700)
        agent=fixture/'.local/libexec/lanpilot-tls/rwn-desktop-agent'
        service=fixture/'Library/LaunchAgents/com.lanpilot.desktop-tls.plist'
        trust=fixture/'.local/share/lanpilot/identity-v1'
        for directory in [agent.parent,service.parent,trust]:
            directory.mkdir(parents=True,exist_ok=True)
        agent.write_bytes(b'EXACT PERSONAL RUNTIME FIXTURE'); agent.chmod(0o700)
        for name in ['root.der','client-ocsp.der']:
            (trust/name).write_bytes(b'public fixture'); (trust/name).chmod(0o600)
        args=[str(agent),'--stream-visual-tls','127.0.0.1','45443','a1b2','a'*64,str(trust/'root.der'),
              'interactive','exact-only',str(trust/'client-ocsp.der'),'--clipboard-text']
        data=dict(Label='com.lanpilot.desktop-tls',ProgramArguments=args,LimitLoadToSessionType='Aqua',
                  RunAtLoad=True,KeepAlive=True,ThrottleInterval=10,Umask=63,
                  WorkingDirectory=str(fixture),StandardOutPath='/dev/null',StandardErrorPath='/dev/null')
        service.write_bytes(plistlib.dumps(data)); service.chmod(0o600)
        before=(module.digest(agent),module.digest(service))
        package=root/'LanPilot-Mac-Personal.pkg'
        contract=module.assemble(fixture,package,license_path)
        rejected=False
        try: module.assemble(fixture,package,license_path)
        except ValueError: rejected=True
        assert rejected
        expanded=root/'expanded'; run('/usr/sbin/pkgutil','--expand-full',package,expanded)
        distribution=ET.parse(expanded/'Distribution').getroot()
        assert distribution.find('domains').attrib==dict(enable_anywhere='false',enable_currentUserHome='true',enable_localSystem='false')
        assert distribution.findtext('title') == 'LanPilot'
        assert distribution.find('options').attrib['allow-external-scripts'] == 'false'
        class OfflinePage(HTMLParser):
            def handle_starttag(self, tag, attrs):
                assert tag not in {'script', 'iframe', 'form', 'object', 'embed', 'input'}
                assert not any(k.lower().startswith('on') or k.lower() in {'src', 'href', 'action'} for k,v in attrs)
        for stage in ['welcome', 'conclusion']:
            resource=distribution.find(stage)
            assert resource.attrib==dict(file=stage+'.html', **{'mime-type':'text/html'})
            page=(expanded/'Resources'/resource.attrib['file']).read_text(encoding='utf-8')
            OfflinePage().feed(page)
            assert 'Connect' in page and len(page) < 8192
            assert 'http:' not in page and 'https:' not in page and 'file:' not in page and 'url(' not in page
            assert str(fixture) not in page and str(Path.home()) not in page
        payloads=list(expanded.glob('*.pkg/Payload')); assert len(payloads)==1
        payload=payloads[0]
        files={str(p.relative_to(payload)) for p in payload.rglob('*') if p.is_file()}
        assert files=={'.local/libexec/lanpilot-tls/rwn-desktop-agent','.local/libexec/lanpilot-tls/LICENSE.txt'}
        assert module.digest(payload/'.local/libexec/lanpilot-tls/rwn-desktop-agent')==before[0]
        scripts=payload.parent/'Scripts'
        assert {p.name for p in scripts.iterdir()}=={'contract.plist','preinstall','postinstall','personal-runtime-check.sh'}
        assert plistlib.loads((scripts/'contract.plist').read_bytes())==contract
        post=(scripts/'postinstall').read_text()
        assert '/bin/launchctl kickstart "$personal_job"' in post
        assert 'kickstart -k' not in post and 'bootout' not in post
        # The exact shipped guard is sourced with private fixture arguments only.
        # Production pre/post resolve the real user themselves and expose no override.
        probe=root/'probe.sh'
        probe.write_text('. "$1"\npersonal_check "$2" "$3" "$4" "$5"\n')
        guard=scripts/'personal-runtime-check.sh'; binding=scripts/'contract.plist'
        run('/bin/sh',probe,guard,fixture,os.getuid(),binding,'preinstall')
        run('/bin/sh',probe,guard,fixture,os.getuid(),binding,'postinstall')
        agent.write_bytes(b'changed runtime')
        run('/bin/sh',probe,guard,fixture,os.getuid(),binding,'preinstall',success=False)
        agent.write_bytes(b'EXACT PERSONAL RUNTIME FIXTURE')
        saved=service.read_bytes(); service.write_bytes(saved+b' ')
        run('/bin/sh',probe,guard,fixture,os.getuid(),binding,'preinstall',success=False)
        service.write_bytes(saved)
        agent.unlink()
        run('/bin/sh',probe,guard,fixture,os.getuid(),binding,'preinstall')
        run('/bin/sh',probe,guard,fixture,os.getuid(),binding,'postinstall',success=False)
        agent.symlink_to(root/'absent')
        run('/bin/sh',probe,guard,fixture,os.getuid(),binding,'preinstall',success=False)
        agent.unlink(); agent.write_bytes(b'EXACT PERSONAL RUNTIME FIXTURE'); agent.chmod(0o700)
        (fixture/'Applications/LanPilot.app').mkdir(parents=True)
        run('/bin/sh',probe,guard,fixture,os.getuid(),binding,'preinstall',success=False)
        shutil.rmtree(fixture/'Applications')
        assert before==(module.digest(agent),module.digest(service))
    print('personal_installer=PASS exact_runtime=1 keys_in_payload=0 profile_in_payload=0 negative_guards=5 install_operations=0 launchd_operations=0')


if __name__=='__main__': main()
