## [IrisCTF2025] checksumz

```c
struct checksum_buffer {
	loff_t pos;
	char state[512];
	size_t size;
	size_t read;
	char* name;
	uint32_t s1;
	uint32_t s2;
};

static loff_t checksumz_llseek(struct file *file, loff_t offset, int whence) {
	struct checksum_buffer* buffer = file->private_data;

	switch (whence) {
		case SEEK_SET:
			buffer->pos = offset;  // 这里可以直接修改 buffer->pos
			break;
		case SEEK_CUR:
			buffer->pos += offset;
			break;
		case SEEK_END:
			buffer->pos = buffer->size - offset;
			break;
		default:
			return -EINVAL;
	}

	if (buffer->pos < 0)
		buffer->pos = 0;

	if (buffer->pos >= buffer->size)
		buffer->pos = buffer->size - 1;

	return buffer->pos;
}

static ssize_t checksumz_write_iter(struct kiocb *iocb, struct iov_iter *from) {
        struct checksum_buffer* buffer = iocb->ki_filp->private_data;
        size_t bytes = iov_iter_count(from);

        if (!buffer)
			return -EBADFD;
        if (!bytes)
			return 0;

		ssize_t copied = copy_from_iter(buffer->state + buffer->pos, min(bytes, 16), from); 
		// 可以写 16 字节

		buffer->pos += copied;
		if (buffer->pos >= buffer->size)
			buffer->pos = buffer->size - 1;

        return copied;
}
```

思路：先用 `lseek` 修改 `buffer->pos` 到最大值 511，然后写 16 字节把 `name` 指针改掉。
