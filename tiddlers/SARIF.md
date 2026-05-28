Static Analysis Results Interchange Format

OASIS 定义它作为静态分析工具输出结果的标准格式

```json
{
  "ruleId": "NULL_DEREFERENCE",
  "message": "pointer p may be null",
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": {"uri": "src/foo.c"},
        "region": {"startLine": 123}
      }
    }
  ],
  "codeFlows": [
    {
      "threadFlows": [
        {"location": "p assigned NULL"},
        {"location": "p dereferenced"}
      ]
    }
  ]
}
```
