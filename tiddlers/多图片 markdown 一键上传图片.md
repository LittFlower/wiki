markdown 图片里的图片如果较多的话一张一张上传到图床有点蠢。

可以写个一键脚本，靠正则表达式匹配替换。

本地写的时候，为了方便匹配文章中出图片的位置，一般使用一个标准的命名，可以用 `![001.jpg](001.jpg)`

同时真实的图片可以放在目录里，不影响编写时的所见即所得。

云端图床用的是[聚合图床](https://www.superbed.cn/help#item=4)，以下是个例子：

```python
import requests
url = "https://api.superbed.cn/upload"
# 通过链接上传
resp = requests.post(url, data={"token": "123456789", "src": "https://ww1.sinaimg.cn/large/005YhI8igy1fv09liyz9nj30qo0hsn0e"})
# 通过文件上传
resp = requests.post(url, data={"token": "123456789"}, files={"file": open("demo.jpg", "rb")})
print(resp.json())
```

我用的是 hugo，所以发布文章是在写好 md 之后的事情。