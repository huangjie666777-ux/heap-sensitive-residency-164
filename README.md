# heapx — Java 堆保留内存分析后端

定位 Java 堆中保留大块内存的对象。纯后端：Java 17 + Javalin 6.5.0，
HPROF 读取使用 NetBeans Profiler 库（RELEASE230，仅用于读取对象与浅堆字节），
图构建、支配分析与保留量计算均为自研实现。

## 构建与启动

```bash
mvn -B package          # 编译 + 跑测试 + 生成可执行 jar
java -jar target/heapx-1.0.0-jar-with-dependencies.jar
# 默认端口 7070，可用 PORT 环境变量覆盖：PORT=7717 java -jar ...
```

## 分析口径

- **节点**：普通实例与数组（对象数组、原始数组）。不模拟类加载器。
- **根**：转储中的 GC 根（线程栈、JNI、监视器等）以及类静态引用指向的对象。
  分析时加入一个虚拟根，指向所有根对象。
- **边**：实例引用字段（含继承字段，标签为 `声明类#字段名`）与对象数组元素
  （标签为 `[下标]`）。排除 `java.lang.ref.Reference` 声明的 `referent`
  （软/弱/虚引用不算强引用），忽略 null 引用。
- **支配**：对象 d 支配 o 当且仅当从虚拟根到 o 的每条路径都经过 d。
  立即支配者用 Cooper–Harvey–Kennedy 迭代算法在逆后序上计算，
  正确处理环、共享子图与多个根。
- **保留字节**：支配子树中所有对象的浅堆字节之和（不是可达总和）。
  不可达对象单独标记（`unreachable: true`），不参与保留排行。
- **浅堆字节**：取自 NetBeans 读取器的 `Instance.getSize()`；保留量不使用
  任何库计算结果。
- **对象 ID**：HPROF 原始对象 ID 的十六进制字符串（`0x` 前缀），无损传递；
  查询时带不带 `0x` 前缀均可。

## 限制

- 文件 ≤ 100 MiB（超限 422，请求体超限 413）
- 对象 ≤ 50,000（`HEAPX_MAX_OBJECTS` 可调）
- 边 ≤ 200,000（`HEAPX_MAX_EDGES` 可调）
- 损坏文件返回 400；任何失败都不会发布半份分析。
- 每次上传得到独立 `analysisId`，并发上传/查询互不影响；
  `DELETE` 释放全部资源，无持久化。

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/analyses` | 上传 HPROF（multipart 字段 `file` 或原始请求体），返回 `analysisId` |
| GET | `/api/analyses/{id}` | 分析概要（对象/边/不可达数） |
| GET | `/api/analyses/{id}/retained?limit=50&offset=0` | 按保留字节降序的对象列表 |
| GET | `/api/analyses/{id}/objects/{hexId}` | 单个对象：类、浅堆、保留量、立即支配者 |
| GET | `/api/analyses/{id}/objects/{hexId}/path` | 到任一根的最短强引用路径（逐边字段/下标） |
| POST | `/api/analyses/{id}/cut-plan` | 最低代价断引用规划：使目标对象全部不可达的最小代价引用集合 |
| POST | `/api/analyses/{id}/scans` | 提交 1–16 条敏感值规则，扫描 byte[]/char[] 载荷，返回不可变 `scanId` |
| GET | `/api/analyses/{id}/scans/{scanId}` | 重新获取扫描结果（不可变） |
| GET | `/api/analyses/{id}/scans/{scanId}/export` | 下载按扫描命中遮除（置零）的真实 HPROF 副本 |
| DELETE | `/api/analyses/{id}` | 删除分析并释放资源 |

## 敏感值扫描与遮除导出

提交规则（JSON，原文不会出现在任何响应、错误消息或日志中）：

```json
{"rules": [{"id": "token", "value": "tok_live_9f8e7d6c5b"},
           {"id": "pw", "value": "correct horse battery"}]}
```

- **规则**：1–16 条；`id` 为 1–64 个可打印 ASCII 字符且本次请求内唯一；
  `value` 为 4–128 个可打印 ASCII 字符（0x20–0x7E）。重复 id、过短/过长、
  非可打印字符一律 400 拒绝，错误消息只含规则 id，不回显原文。
- **扫描口径**：只扫描 `byte[]` 与 `char[]` 的载荷，按 ASCII 字节（byte[]）
  或等值字符（char[]，大端 UTF-16 单元高位为 0）精确匹配；枚举全部位置，
  含重叠命中、多规则命中同一数组、不可达数组。不跨数组匹配，不识别
  UTF-8/UTF-16 等其他编码。载荷位置由自研的 HPROF 记录遍历器定位
  （兼容 4/8 字节 ID 与 HEAP_DUMP_SEGMENT 分段堆），不做全文件字符串搜索。
- **结果**：绑定不可变 `scanId`，每条命中含 `ruleId`、`arrayId`（对象十六进制
  ID）、`arrayType`、`elementOffset`/`elementLength`（以数组元素计）、
  `reachable`；可达命中附持有数组的最短强引用根路径 `rootPath`。

导出（`GET .../scans/{scanId}/export`）返回真实 HPROF 副本
（`application/octet-stream` 附件），响应头：

- `X-Scrubbed-Arrays`：实际修改的去重数组个数（共享数组只改一次，
  多个持有者读到同一份遮除值）；
- `X-Scrubbed-Bytes`：实际改写的字节数（命中区间按数组求并集，
  重叠/相邻区间不重复计数）。

遮除语义与边界：

- 只把命中区间在副本中置零；未命中载荷、对象 ID、GC 根、引用、类型、
  数组长度及所有其他记录字节逐一保留。副本可重新上传分析，原排名、
  根路径与断引用规划结果不变。
- 不改动 HPROF STRING 记录（类名、字段名等文本）与任何非 byte[]/char[]
  内容——**这不是完全匿名化**，敏感值若同时存在于字符串记录等其他
  结构中不会被移除。
- 原转储在分析存续期间保留用于扫描与导出；导出失败不会发布半份文件；
  `DELETE` 删除源转储、扫描结果与导出临时文件，之后扫描/导出一律 404。
  并发扫描/导出/查询互不影响，沿用原有的文件/对象/边规模限制。

## 断引用规划（cut-plan）

请求体（JSON）：

```json
{
  "targets": ["0x7090176a8", "0x7090276b8"],
  "candidates": [
    {"source": "0x709017690", "via": "java.util.ArrayList#elementData",
     "target": "0x7090676f8", "cost": 15},
    {"source": "0x7090676f8", "via": "[0]", "target": "0x7090176a8", "cost": 10}
  ]
}
```

- `targets`：要释放的对象 ID（十六进制，1–32 个，必须存在）。
- `candidates`：允许断开的强引用清单（≤1000 条）。`via` 与图查询返回的引用
  标签一致（`声明类#字段名` 或 `[下标]`）；`cost` 为 1–1,000,000,000 的整数。
  源/目标对象必须存在、引用必须真实存在；重复候选、非法代价、不存在的引用
  一律 400 拒绝。
- 求解口径：所有 GC 根与静态引用目标是固定根，仅候选中的引用可断开。
  在所有目标上做**一次**最小 s-t 割（超源→各根、各目标→超汇，不可断边容量
  无穷），精确给出使全部目标不可达的最小总代价集合——共享前缀只付一次，
  环、多根、同对象间不同字段都联合优化，等价最优解返回任意一个。
  已不可达的目标不产生费用。

成功响应（200）：

```json
{
  "feasible": true,
  "totalCost": 15,
  "cuts": [{"source": "0x709017690", "via": "java.util.ArrayList#elementData",
            "target": "0x7090676f8", "cost": 15}],
  "newlyUnreachable": {"count": 21, "shallowBytes": 1311400, "ids": ["0x..."]},
  "alreadyUnreachableTargets": []
}
```

`newlyUnreachable` 是断开前后根可达集合之差（新增不可达对象 ID、数量、
浅堆字节总和），原本不可达的对象不计入，也不使用任何旧保留值累加。

无解响应（422）：附一条完全由不可断引用组成的根→目标证据路径；
目标本身是根时 `targetIsRoot: true` 且路径为空。

```json
{
  "feasible": false,
  "error": "target stays reachable through references that are not in the cuttable list",
  "evidence": {"target": "0x7090176a8", "targetIsRoot": false,
               "uncuttablePath": [{"from": "0x709017690", "via": "...", "to": "0x..."}]}
}
```

规划是只读操作：不改变原图、保留排名与路径查询；请求间完全隔离；
分析删除后再规划返回 404。

## curl 演示（真实堆转储）

```bash
# 制造一个真实堆转储
cat > Leaky.java <<'J'
import java.util.*;
public class Leaky {
  static List<byte[]> cache = new ArrayList<>();
  public static void main(String[] a) throws Exception {
    for (int i = 0; i < 20; i++) cache.add(new byte[64 * 1024]);
    Thread.sleep(120_000);
  }
}
J
javac Leaky.java && java Leaky &
jmap -dump:live,format=b,file=real.hprof $!

# 上传（4.7 MiB / 24,066 对象 / 36,691 边）
curl -s http://localhost:7717/api/analyses -F "file=@real.hprof"
# => {"analysisId":"001c721c-...","objects":24066,"edges":36691,"unreachableObjects":207}

# 保留排行：Leaky.cache 的 ArrayList 保留 1.31 MB（20 个 64 KiB 字节数组）
curl -s "http://localhost:7717/api/analyses/<analysisId>/retained?limit=5"

# 根路径：ArrayList --elementData--> Object[] --[0]--> byte[]
curl -s "http://localhost:7717/api/analyses/<analysisId>/objects/0xfc01ded0/path"

# 断引用规划：断开 elementData（代价 15）一次释放整个缓存
curl -s -X POST "http://localhost:7717/api/analyses/<analysisId>/cut-plan" \
  -H 'Content-Type: application/json' \
  -d '{"targets":["0xfc01ded0"],"candidates":[
        {"source":"0x...","via":"java.util.ArrayList#elementData","target":"0x...","cost":15},
        {"source":"0x...","via":"[0]","target":"0xfc01ded0","cost":10}]}'
# => {"feasible":true,"totalCost":15,"cuts":[...elementData...],
#     "newlyUnreachable":{"count":21,"shallowBytes":1311400,...}}

# 敏感值扫描：提交规则（原文不回显）
curl -s -X POST "http://localhost:7717/api/analyses/<analysisId>/scans" \
  -H 'Content-Type: application/json' \
  -d '{"rules":[{"id":"token","value":"tok_live_9f8e7d6c5b"}]}'
# => {"scanId":"ebe9ebf5-...","hitCount":3,"hits":[{"ruleId":"token",
#      "arrayId":"0x709a17710","arrayType":"byte[]","elementOffset":0,
#      "elementLength":19,"reachable":true,"rootPath":[...]},...]}

# 下载遮除副本（命中区间已置零）
curl -s -D - -o scrubbed.hprof \
  "http://localhost:7717/api/analyses/<analysisId>/scans/<scanId>/export"
# => HTTP/1.1 200 OK
#    X-Scrubbed-Arrays: 3
#    X-Scrubbed-Bytes: 76

# 副本可重新上传分析：对象/边/排名不变，敏感值已消失
curl -s http://localhost:7717/api/analyses -F "file=@scrubbed.hprof"
# => {"analysisId":"...","objects":21972,"edges":32644,"unreachableObjects":38}

# 释放
curl -s -X DELETE "http://localhost:7717/api/analyses/<analysisId>"
```

## 代码结构

- `heapx.parse.HprofParser` — NetBeans 读取器 → 对象/浅堆/边/根，执行限制
- `heapx.model.HeapModel` — 不可变图（CSR 正/反邻接，id 索引）
- `heapx.graph.DominatorAnalysis` — 虚拟根 + 立即支配者 + 保留量 + 不可达标记
- `heapx.graph.PathFinder` — 反向 BFS 求到根的最短强引用路径
- `heapx.graph.CutPlanner` — 超源/超汇最小 s-t 割（Dinic）求最低代价断引用方案，
  含不可断证据路径与可达集合差计算
- `heapx.scrub.HprofLayout` — HPROF 记录/子记录遍历，定位 byte[]/char[]
  载荷文件偏移（4/8 字节 ID、分段堆）
- `heapx.scrub.PayloadScanner` — 载荷内精确 ASCII 匹配（重叠、多规则、
  byte[]/char[]），不跨数组
- `heapx.scrub.ScrubExporter` — 复制原文件后仅对命中区间并集置零，
  统计去重数组数与实际改写字节数
- `heapx.service.AnalysisService` — 分析注册表、源转储保留、扫描/导出
  生命周期、限制、并发隔离、删除清理
- `heapx.http.Api` / `heapx.Main` — Javalin 路由与启动

## 测试

```bash
mvn -B test
```

- `DominatorAnalysisTest`：合成图验证支配语义（链上共享节点、环、多根共享、
  不可达标记、最短路径用真实边而非支配树边）。
- `CutPlannerTest`：合成图验证最小割语义（共享前缀只断一次、非最短路径上的
  边、环与同对象平行字段、多根、不可断证据、根作为目标、已不可达目标免费、
  新增不可达集合为可达集差）。
- `EndToEndTest`：用自写 HPROF 生成器（4 字节 ID）产出真实转储文件，
  覆盖静态根、JNI 根、继承字段、对象/原始数组、`Reference.referent` 排除、
  不可达对象，并走完整 HTTP 上传 → 排行 → 根路径 → 断引用规划 → 删除流程；
  另验证对象/边超限、损坏文件与非法规划请求（重复候选、非法代价、
  不存在的引用）的拒绝。
- `ScrubTest`：敏感值扫描与遮除导出。覆盖重叠命中、多规则、char[] 与
  不可达数组、根路径附件、非法规则拒绝且不回显原文、命中区间并集置零
  （逐字节校验其余内容不变）、去重数组数与改写字节数、8 字节 ID 与
  分段堆、副本重新上传后排名不变且复扫零命中、删除后扫描/导出 404。
