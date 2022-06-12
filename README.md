# 资产/账号批量上传脚本
所有参数应依据产品中定义的属性变量进行设定，本程序会读取Excel并且进行上传。

## 安装依赖包
在线方式：
 - 在线安装：pip install -r requirements.txt
 - 下载加速：可以在上述命令最后添加，-i https://pypi.tuna.tsinghua.edu.cn/simple
 
离线方式：
 - 下载依赖：pip download --only-binary=:all: -d .\offline -r .\requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
 - 离线安装：pip install --no-index --find-links=.\offline -r .\requirements.txt

## 数据条件
1. 请使用 template.xls，不支持读取xlsx格式
2. 每个 Excel 分成 Device 和 Account 两个sheet，不支持修改sheet的名称。

## 自定义属性
【cusAttrs.xxx】资产或者账号的自定义属性
 - 比如在列中使用列名为：cusAttrs.sysSshPort
 - sysSshPort必须和【数据模型】页面中的属性名保持一致。 
 
【assAttrs.xxx】资产的默认账号的自定义属性，比如：
 - assAttrs.logonAccount
 - assAttrs.reconcileAccount

## 运行方式：
python main.py -a "{address}" -u "{username}" -p "{password}" -f "./template.xls" -m <mode>

mode:
 - data: 仅上传资产账号
 - cpm: 仅处理 Account 页面中的账号，根据 action 列，触发 verify，change，reconcile操作
 - all: 除了上传，资产/账号之外，会在上传后立即触发指定的CPM任务。

### 注意事项
1. 如果资产或账号已经存在，则重复上传会导致失败。

