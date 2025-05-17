## level1.0

启动环境后，内核驱动在 `/challenge` 下，通过 vscode 环境下载到本地分析。

`init_module.c`：

```c
int __cdecl init_module()
{
  __int64 fd; // rbp

  fd = filp_open("/flag", 0LL, 0LL);
  memset(flag, 0, sizeof(flag));
  kernel_read(fd, flag, 128LL, fd + 104);
  filp_close(fd, 0LL);
  proc_entry = (proc_dir_entry *)proc_create("pwncollege", 438LL, 0LL, &fops);
  printk(&unk_BD1);
  printk(&unk_9D0);
  printk(&unk_BD1);
  printk(&unk_A00);
  printk(&unk_A68);
  printk(&unk_AC8);
  printk(&unk_B18);
  printk(&unk_BD8);
  return 0;
}
```

可以看到创建了 `/proc/pwncollege`，这里记录一下 `proc_create` 的作用，可以在 `/proc` 下创建一个文件，用户通过这个文件可以与内核进行交互。

```c
int __fastcall device_open(inode *inode, file *file)
{
  printk(&unk_928);
  return 0;
}

ssize_t __fastcall device_write(file *file, const char *buffer, size_t length, loff_t *offset)
{
  size_t v5; // rdx
  char password[16]; // [rsp+0h] [rbp-28h] BYREF
  unsigned __int64 v8; // [rsp+10h] [rbp-18h]

  v8 = __readgsqword(0x28u);
  printk(&unk_950);
  v5 = 16LL;
  if ( length <= 0x10 )
    v5 = length;
  copy_from_user(password, buffer, v5);
  device_state[0] = (strncmp(password, "gxrgpsxalwuwhrhx", 0x10uLL) == 0) + 1;
  return length;
}

ssize_t __fastcall device_read(file *file, char *buffer, size_t length, loff_t *offset)
{
  const char *v6; // rsi
  size_t v7; // rdx
  unsigned __int64 v8; // rax

  printk(&unk_990);
  v6 = flag;
  if ( device_state[0] != 2 )
  {
    v6 = "device error: unknown state\n";
    if ( device_state[0] <= 2 )
    {
      v6 = "password:\n";
      if ( device_state[0] )
      {
        v6 = "device error: unknown state\n";
        if ( device_state[0] == 1 )
        {
          device_state[0] = 0;
          v6 = "invalid password\n";
        }
      }
    }
  }
  v7 = length;
  v8 = strlen(v6) + 1;
  if ( v8 - 1 <= length )
    v7 = v8 - 1;
  return v8 - 1 - copy_to_user(buffer, v6, v7);
}
```

可以看到只需要 `device_write` 将 `device_state[0]` 修改为 `2`，然后就可以得到 flag 了。

exp:

```c
# include <stdio.h>
# include <fcntl.h>

int main() {
    char flag[100];
    int fd = open("/proc/pwncollege", 2);
    write(fd, "gxrgpsxalwuwhrhx", 16);
    read(fd, flag, 0x100);
    printf("%s", flag);
    return 0;
}
```

