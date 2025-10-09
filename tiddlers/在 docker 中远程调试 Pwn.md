**应用场景**：在本地通了远程不通的时候，希望快速通过出题人提供的 dockerfile 复现远程环境并快速 debug

**项目地址**：ex 师傅写的 [debug_server](https://github.com/Ex-Origin/debug-server)

**使用方法**：
1. 将项目 clone 到本地，执行 `make`
2. 修改 dockerfile，将编译出的 `debug-server` 文件 cp 到题目环境里
3. 修改 docker-compose.yml 或者 `docker run` 命令，使用 host 模式
4. 在 docker 里运行 `./debug-server -e ./run`，本地运行 `python3 gdbpwn.py 127.0.0.1`
5. 修改 exp.py，添加以下模板即可调试：
```python
def attach(script=''):
    attach_host = "127.0.0.1"
    attach_port = 9545
    tmp_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    gdb_script = re.sub(r'#.*', '', f'''
define pr
    x/16gx $rebase(0x0)
end

b *$rebase(0x0)
''' + '\n' + script)
    gdbinit = '/tmp/gdb_script_' + attach_host
    script_f = open(gdbinit, 'w')
    script_f.write(gdb_script)
    script_f.close()
    _attach_host = attach_host
    if attach_host.find(':') == -1:
        _attach_host = '::ffff:' + attach_host
    tmp_sock.sendto(struct.pack('BB', 0x02, len(gdbinit.encode())) + gdbinit.encode(), (_attach_host, attach_port))
    tmp_sock.recvfrom(4096)
    tmp_sock.close()
    log.success('attach successfully')

io = remote("127.0.0.1", 9541)
attach()
```

**注意事项**：
1. 如果你是 Arch Linux 用户，由于官方源中 gdb-mutiarch 已经被合并到 gdb 包内，所以已经不存在 `/usr/bin/gdb-mutiarch`，将 gdbpwn.py 的第 77 行修改为 `args = ['/usr/bin/gdb', '-q', '-ex', f'target remote {server_ip}:{gdb_port}', '-x', gdbscript]` 即可
2. docker-compose 设置 host 模式的方法是添加 `network_mode: "host"` 项