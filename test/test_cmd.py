#./build/us./build/bi./build/env python3


CASES = r'''
$ ./build/client zscore asdf n1
(nil)
$ ./build/client zquery xxx 1 asdf 1 10
(arr) len=0
(arr) end
$ ./build/client zadd zset 1 n1
(int) 1
$ ./build/client zadd zset 2 n2
(int) 1
$ ./build/client zadd zset 1.1 n1
(int) 0
$ ./build/client zscore zset n1
(dbl) 1.1
$ ./build/client zquery zset 1 "" 0 10
(arr) len=4
(str) n1
(dbl) 1.1
(str) n2
(dbl) 2
(arr) end
$ ./build/client zquery zset 1.1 "" 1 10
(arr) len=2
(str) n2
(dbl) 2
(arr) end
$ ./build/client zquery zset 1.1 "" 2 10
(arr) len=0
(arr) end
$ ./build/client zrem zset adsf
(int) 0
$ ./build/client zrem zset n1
(int) 1
$ ./build/client zquery zset 1 "" 0 10
(arr) len=2
(str) n2
(dbl) 2
(arr) end
'''


import shlex
import subprocess

cmds = []
outputs = []
lines = CASES.splitlines()
for x in lines:
    x = x.strip()
    if not x:
        continue
    if x.startswith('$ '):
        cmds.append(x[2:])
        outputs.append('')
    else:
        outputs[-1] = outputs[-1] + x + '\n'

assert len(cmds) == len(outputs)
for cmd, expect in zip(cmds, outputs):
    x= subprocess.check_output(shlex.split(cmd))
    out = x.decode('utf-8')
    assert out == expect, f'cmd:{cmd} out:{out}'
