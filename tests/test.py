import subprocess
import os


env = os.environ.copy()
env['LD_LIBRARY_PATH'] = '../allocator'
result = subprocess.run(["./bin/test-realloc-no-split"], capture_output=True, env=env)
print(result.stdout)
