import os
import platform
import collections

def apply_windows_patches():
    """
    Apply necessary patches for Windows environments
    """
    if os.name == 'nt':
        try:
            _original_uname = platform.uname
            def mocked_uname():
                UNameResult = collections.namedtuple('uname_result', ['system', 'node', 'release', 'version', 'machine', 'processor'])
                return UNameResult('Windows', 'LOCAL_MACHINE', '10', '10.0.19045', 'AMD64', 'Intel64 Family')
            platform.uname = mocked_uname
        except Exception as e:
            print(f"⚠️ Failed to apply Windows patch: {e}")
